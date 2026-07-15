//! LnvMSRIO.sys Driver Backend - PhysicalMemoryDriver Implementation
//!
//! Device: \\.\WinMsrDev
//! Read IOCTL:  0x9C406104 (METHOD_BUFFERED)
//! Write IOCTL: 0x9C40A108 (METHOD_BUFFERED)
//!
//! Input struct (16 bytes):
//!   { phys_addr: u64, access_size: u32, count: u32 }

use std::ffi::c_void;
use std::io;
use std::mem;
use std::ptr;

use super::PhysicalMemoryDriver;

// =============================================================================
// FFI
// =============================================================================

type HANDLE = *mut c_void;
type DWORD = u32;
type BOOL = i32;
type LPCWSTR = *const u16;

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
const GENERIC_READ: DWORD = 0x80000000;
const GENERIC_WRITE: DWORD = 0x40000000;
const FILE_SHARE_READ: DWORD = 0x00000001;
const FILE_SHARE_WRITE: DWORD = 0x00000002;
const OPEN_EXISTING: DWORD = 3;
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;

extern "system" {
    fn CreateFileW(
        file_name: LPCWSTR,
        desired_access: DWORD,
        share_mode: DWORD,
        security_attributes: *mut c_void,
        creation_disposition: DWORD,
        flags_and_attributes: DWORD,
        template_file: HANDLE,
    ) -> HANDLE;

    fn DeviceIoControl(
        device: HANDLE,
        io_control_code: DWORD,
        in_buffer: *const c_void,
        in_buffer_size: DWORD,
        out_buffer: *mut c_void,
        out_buffer_size: DWORD,
        bytes_returned: *mut DWORD,
        overlapped: *mut c_void,
    ) -> BOOL;

    fn CloseHandle(handle: HANDLE) -> BOOL;
}

// =============================================================================
// IOCTL Codes
// =============================================================================

/// Physical Memory READ (MmMapIoSpace, METHOD_BUFFERED)
const IOCTL_PHYS_MEM_READ: DWORD = 0x9C406104;

/// Physical Memory WRITE (MmMapIoSpace, METHOD_BUFFERED)
const IOCTL_PHYS_MEM_WRITE: DWORD = 0x9C40A108;

/// Driver version query
const IOCTL_GET_VERSION: DWORD = 0x9C402000;

// =============================================================================
// Wire Structures
// =============================================================================

/// Read input: 16 bytes
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PhysMemReadInput {
    /// Target physical address
    physical_address: u64,
    /// Element access size: 1=BYTE, 2=WORD, 4=DWORD, 8=QWORD
    access_size: u32,
    /// Number of elements to read (total bytes = access_size * count)
    count: u32,
}

/// Write input: 16-byte header followed by data payload
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PhysMemWriteHeader {
    /// Target physical address
    physical_address: u64,
    /// Element access size
    access_size: u32,
    /// Number of elements to write
    count: u32,
}

// =============================================================================
// Driver Handle
// =============================================================================

/// Handle to the LnvMSRIO kernel driver
pub struct LnvMsrioDriver {
    handle: HANDLE,
}

impl LnvMsrioDriver {
    const DEVICE_PATH: &'static str = "\\\\.\\WinMsrDev";

    /// Open a handle to the LnvMSRIO device
    pub fn open() -> io::Result<Self> {
        let wide: Vec<u16> = Self::DEVICE_PATH
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { handle })
    }

    /// Raw IOCTL dispatch
    fn ioctl(
        &self,
        code: DWORD,
        input: *const u8,
        input_len: DWORD,
        output: *mut u8,
        output_len: DWORD,
    ) -> io::Result<u32> {
        let mut bytes_returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                code,
                input as *const c_void,
                input_len,
                output as *mut c_void,
                output_len,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_returned)
        }
    }

    /// Query driver version to verify connectivity
    pub fn get_version(&self) -> io::Result<u32> {
        let mut version: u32 = 0;
        self.ioctl(
            IOCTL_GET_VERSION,
            ptr::null(),
            0,
            &mut version as *mut _ as *mut u8,
            4,
        )?;
        Ok(version)
    }
}

// =============================================================================
// PhysicalMemoryDriver trait implementation
// =============================================================================

impl PhysicalMemoryDriver for LnvMsrioDriver {
    fn read_physical(&self, phys_addr: u64, size: usize) -> io::Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        let input = PhysMemReadInput {
            physical_address: phys_addr,
            access_size: 1,
            count: size as u32,
        };

        let mut buffer = vec![0u8; size];

        let bytes_returned = self.ioctl(
            IOCTL_PHYS_MEM_READ,
            &input as *const _ as *const u8,
            mem::size_of::<PhysMemReadInput>() as DWORD,
            buffer.as_mut_ptr(),
            size as DWORD,
        )?;

        if bytes_returned as usize != size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("expected {} bytes, got {}", size, bytes_returned),
            ));
        }

        Ok(buffer)
    }

    fn write_physical(&self, phys_addr: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Build wire buffer: 16-byte header + data payload
        let total_size = mem::size_of::<PhysMemWriteHeader>() + data.len();
        let mut buf = vec![0u8; total_size];

        let header = PhysMemWriteHeader {
            physical_address: phys_addr,
            access_size: 1,
            count: data.len() as u32,
        };

        unsafe {
            ptr::copy_nonoverlapping(
                &header as *const _ as *const u8,
                buf.as_mut_ptr(),
                mem::size_of::<PhysMemWriteHeader>(),
            );
        }
        buf[16..].copy_from_slice(data);

        self.ioctl(
            IOCTL_PHYS_MEM_WRITE,
            buf.as_ptr(),
            total_size as DWORD,
            ptr::null_mut(),
            0,
        )?;

        Ok(())
    }
}

// =============================================================================
// Cleanup
// =============================================================================

impl Drop for LnvMsrioDriver {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.handle); }
            self.handle = INVALID_HANDLE_VALUE;
        }
    }
}

unsafe impl Send for LnvMsrioDriver {}
