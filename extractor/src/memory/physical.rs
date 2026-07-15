//! Safe physical memory access wrapper.
//! Validates addresses against known-safe ranges before issuing driver reads/writes.
//! Safe ranges confirmed on Windows 11 Build 26200.

use std::io;

use crate::drivers::PhysicalMemoryDriver;

// --- Safe physical address ranges (Build 26200, confirmed via e820 map) ---

/// Low conventional memory (real-mode IVT, BDA, EBDA excluded at boundaries)
const SAFE_LOW_START: u64 = 0x001000;
const SAFE_LOW_END: u64 = 0x09F000;

/// Main RAM below 4 GB (above 1 MB, below PCI hole)
const SAFE_MAIN_START: u64 = 0x100000;
const SAFE_MAIN_END: u64 = 0x581EE000;

/// Boundary page just below 64-bit region
const SAFE_BOUNDARY_START: u64 = 0x63FFF000;
const SAFE_BOUNDARY_END: u64 = 0x64000000;

/// RAM above 4 GB (remapped above PCI hole)
const SAFE_HIGH_START: u64 = 0x100000000;
const SAFE_HIGH_END: u64 = 0x880000000;

/// Check whether a physical address falls within a known-safe RAM range.
/// Returns false for MMIO, ACPI, reserved, or unmapped regions.
#[inline]
pub fn is_safe_phys_addr(addr: u64) -> bool {
    (addr >= SAFE_LOW_START && addr < SAFE_LOW_END)
        || (addr >= SAFE_MAIN_START && addr < SAFE_MAIN_END)
        || (addr >= SAFE_BOUNDARY_START && addr < SAFE_BOUNDARY_END)
        || (addr >= SAFE_HIGH_START && addr < SAFE_HIGH_END)
}

/// Check that an entire range [addr, addr+len) is within safe memory.
#[inline]
fn is_range_safe(addr: u64, len: u64) -> bool {
    if len == 0 {
        return false;
    }
    let end = addr.saturating_add(len);
    // The entire range must reside within a single safe region
    (addr >= SAFE_LOW_START && end <= SAFE_LOW_END)
        || (addr >= SAFE_MAIN_START && end <= SAFE_MAIN_END)
        || (addr >= SAFE_BOUNDARY_START && end <= SAFE_BOUNDARY_END)
        || (addr >= SAFE_HIGH_START && end <= SAFE_HIGH_END)
}

/// Safe wrapper around a PhysicalMemoryDriver that validates all accesses.
pub struct SafePhysicalReader<'a> {
    driver: &'a dyn PhysicalMemoryDriver,
}

impl<'a> SafePhysicalReader<'a> {
    /// Wrap a driver with address validation.
    pub fn new(driver: &'a dyn PhysicalMemoryDriver) -> Self {
        Self { driver }
    }

    /// Read a u64 from a validated physical address.
    pub fn read_u64_safe(&self, addr: u64) -> io::Result<u64> {
        if !is_range_safe(addr, 8) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("physical read_u64 at 0x{:X} is outside safe ranges", addr),
            ));
        }
        self.driver.read_physical_u64(addr)
    }

    /// Read a u32 from a validated physical address.
    pub fn read_u32_safe(&self, addr: u64) -> io::Result<u32> {
        if !is_range_safe(addr, 4) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("physical read_u32 at 0x{:X} is outside safe ranges", addr),
            ));
        }
        self.driver.read_physical_u32(addr)
    }

    /// Write bytes to a validated physical address.
    pub fn write_safe(&self, addr: u64, data: &[u8]) -> io::Result<()> {
        if !is_range_safe(addr, data.len() as u64) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "physical write of {} bytes at 0x{:X} is outside safe ranges",
                    data.len(),
                    addr
                ),
            ));
        }
        self.driver.write_physical(addr, data)
    }

    /// Read an arbitrary byte buffer, validating in page-aligned chunks.
    /// The entire range must fall within a single safe region.
    pub fn read_bytes_safe(&self, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        if !is_range_safe(addr, len as u64) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "physical read of {} bytes at 0x{:X} is outside safe ranges",
                    len, addr
                ),
            ));
        }
        self.driver.read_physical(addr, len)
    }

    /// Expose underlying driver for callers that handle validation themselves.
    pub fn inner(&self) -> &dyn PhysicalMemoryDriver {
        self.driver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_ranges() {
        // Low conventional
        assert!(is_safe_phys_addr(0x1000));
        assert!(is_safe_phys_addr(0x9E000));
        assert!(!is_safe_phys_addr(0x9F000)); // end exclusive

        // Main below-4GB
        assert!(is_safe_phys_addr(0x100000));
        assert!(is_safe_phys_addr(0x581ED000));
        assert!(!is_safe_phys_addr(0x581EE000));

        // Boundary page
        assert!(is_safe_phys_addr(0x63FFF000));
        assert!(!is_safe_phys_addr(0x64000000));

        // High RAM
        assert!(is_safe_phys_addr(0x100000000));
        assert!(is_safe_phys_addr(0x87FFFFFFF));
        assert!(!is_safe_phys_addr(0x880000000));

        // Known-bad: null page, PCI hole, MMIO
        assert!(!is_safe_phys_addr(0x0));
        assert!(!is_safe_phys_addr(0xFED00000)); // HPET
        assert!(!is_safe_phys_addr(0xFEE00000)); // LAPIC
    }

    #[test]
    fn test_range_validation() {
        // Entirely within main region
        assert!(is_range_safe(0x100000, 0x1000));
        // Crosses boundary out of main region
        assert!(!is_range_safe(0x581ED000, 0x2000));
        // Zero length
        assert!(!is_range_safe(0x100000, 0));
        // Overflow
        assert!(!is_range_safe(u64::MAX, 8));
    }
}
