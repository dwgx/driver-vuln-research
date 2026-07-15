//! Windows Service Control Manager (SCM) wrapper
//!
//! Zero-dependency FFI to advapi32.dll for driver lifecycle management.
//! Handles: create, start, stop, delete kernel driver services.

use std::ffi::c_void;
use std::io;
use std::ptr;

// =============================================================================
// FFI Types and Constants
// =============================================================================

type HANDLE = *mut c_void;
type DWORD = u32;
type BOOL = i32;
type LPCWSTR = *const u16;

const SC_MANAGER_ALL_ACCESS: DWORD = 0xF003F;
const SERVICE_ALL_ACCESS: DWORD = 0xF01FF;
const SERVICE_KERNEL_DRIVER: DWORD = 0x00000001;
const SERVICE_DEMAND_START: DWORD = 0x00000003;
const SERVICE_ERROR_IGNORE: DWORD = 0x00000000;
const SERVICE_CONTROL_STOP: DWORD = 0x00000001;

#[repr(C)]
struct ServiceStatus {
    service_type: DWORD,
    current_state: DWORD,
    controls_accepted: DWORD,
    win32_exit_code: DWORD,
    service_specific_exit_code: DWORD,
    check_point: DWORD,
    wait_hint: DWORD,
}

extern "system" {
    fn OpenSCManagerW(
        machine_name: LPCWSTR,
        database_name: LPCWSTR,
        desired_access: DWORD,
    ) -> HANDLE;

    fn CreateServiceW(
        sc_manager: HANDLE,
        service_name: LPCWSTR,
        display_name: LPCWSTR,
        desired_access: DWORD,
        service_type: DWORD,
        start_type: DWORD,
        error_control: DWORD,
        binary_path_name: LPCWSTR,
        load_order_group: LPCWSTR,
        tag_id: *mut DWORD,
        dependencies: LPCWSTR,
        service_start_name: LPCWSTR,
        password: LPCWSTR,
    ) -> HANDLE;

    fn OpenServiceW(
        sc_manager: HANDLE,
        service_name: LPCWSTR,
        desired_access: DWORD,
    ) -> HANDLE;

    fn StartServiceW(
        service: HANDLE,
        num_service_args: DWORD,
        service_arg_vectors: *const LPCWSTR,
    ) -> BOOL;

    fn ControlService(
        service: HANDLE,
        control: DWORD,
        service_status: *mut ServiceStatus,
    ) -> BOOL;

    fn DeleteService(service: HANDLE) -> BOOL;

    fn CloseServiceHandle(handle: HANDLE) -> BOOL;
}

// =============================================================================
// Helper
// =============================================================================

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// =============================================================================
// ServiceManager
// =============================================================================

/// Manages kernel driver services via the Windows SCM
pub struct ServiceManager {
    scm_handle: HANDLE,
}

impl ServiceManager {
    /// Open a connection to the local SCM with full access
    pub fn connect() -> io::Result<Self> {
        let handle = unsafe {
            OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS)
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { scm_handle: handle })
    }

    /// Register a new kernel driver service
    pub fn create(&self, name: &str, driver_path: &str) -> io::Result<()> {
        let wide_name = to_wide(name);
        let wide_path = to_wide(driver_path);

        let svc_handle = unsafe {
            CreateServiceW(
                self.scm_handle,
                wide_name.as_ptr(),
                wide_name.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE,
                wide_path.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };

        if svc_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        unsafe { CloseServiceHandle(svc_handle); }
        Ok(())
    }

    /// Start a registered driver service
    pub fn start(&self, name: &str) -> io::Result<()> {
        let wide_name = to_wide(name);
        let svc_handle = unsafe {
            OpenServiceW(self.scm_handle, wide_name.as_ptr(), SERVICE_ALL_ACCESS)
        };
        if svc_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        let result = unsafe { StartServiceW(svc_handle, 0, ptr::null()) };
        let err = if result == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };

        unsafe { CloseServiceHandle(svc_handle); }
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Stop a running driver service
    pub fn stop(&self, name: &str) -> io::Result<()> {
        let wide_name = to_wide(name);
        let svc_handle = unsafe {
            OpenServiceW(self.scm_handle, wide_name.as_ptr(), SERVICE_ALL_ACCESS)
        };
        if svc_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        let mut status = ServiceStatus {
            service_type: 0,
            current_state: 0,
            controls_accepted: 0,
            win32_exit_code: 0,
            service_specific_exit_code: 0,
            check_point: 0,
            wait_hint: 0,
        };

        let result = unsafe {
            ControlService(svc_handle, SERVICE_CONTROL_STOP, &mut status)
        };
        let err = if result == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };

        unsafe { CloseServiceHandle(svc_handle); }
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Delete a registered driver service (must be stopped first)
    pub fn delete(&self, name: &str) -> io::Result<()> {
        let wide_name = to_wide(name);
        let svc_handle = unsafe {
            OpenServiceW(self.scm_handle, wide_name.as_ptr(), SERVICE_ALL_ACCESS)
        };
        if svc_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        let result = unsafe { DeleteService(svc_handle) };
        let err = if result == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };

        unsafe { CloseServiceHandle(svc_handle); }
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Drop for ServiceManager {
    fn drop(&mut self) {
        if !self.scm_handle.is_null() {
            unsafe { CloseServiceHandle(self.scm_handle); }
        }
    }
}
