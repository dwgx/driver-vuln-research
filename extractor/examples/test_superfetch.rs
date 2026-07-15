//! Test harness: Superfetch PfnQuery availability
//!
//! Calls NtQuerySystemInformation(SystemSuperfetchInformation = 79) with
//! InfoClass 17 (memory ranges / PFN query) to check whether Superfetch
//! exposes physical page frame data on the current build.
//!
//! Run: cargo run --example test_superfetch
//!
//! Requires: SeProfileSingleProcessPrivilege (run as Administrator)

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::mem;
use std::ptr;

// =============================================================================
// FFI types
// =============================================================================

type HANDLE = *mut c_void;
type NTSTATUS = i32;
type DWORD = u32;
type BOOL = i32;
type LUID = u64;

const STATUS_SUCCESS: NTSTATUS = 0;
const SE_PRIVILEGE_ENABLED: DWORD = 0x00000002;
const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
const TOKEN_QUERY: DWORD = 0x0008;

// SystemSuperfetchInformation
const SYSTEM_SUPERFETCH_INFORMATION: u32 = 79;

// Superfetch info class for PFN / memory range query
const SUPERFETCH_PFN_QUERY: u32 = 17;

// =============================================================================
// Structures
// =============================================================================

#[repr(C)]
struct TOKEN_PRIVILEGES {
    privilege_count: DWORD,
    luid: LUID,
    attributes: DWORD,
}

/// SuperfetchInformation input structure.
/// Version and magic are required for the kernel to accept the call.
#[repr(C)]
#[derive(Clone, Copy)]
struct SUPERFETCH_INFORMATION {
    version: u32,
    magic: u32,
    info_class: u32,
    data: *mut c_void,
    data_length: u32,
}

/// PFN range entry returned by the query
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct PF_PFN_RANGE {
    base_pfn: u64,
    count: u64,
}

// =============================================================================
// FFI imports
// =============================================================================

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;

    fn GetCurrentProcess() -> HANDLE;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(
        process_handle: HANDLE,
        desired_access: DWORD,
        token_handle: *mut HANDLE,
    ) -> BOOL;

    fn LookupPrivilegeValueW(
        system_name: *const u16,
        name: *const u16,
        luid: *mut LUID,
    ) -> BOOL;

    fn AdjustTokenPrivileges(
        token_handle: HANDLE,
        disable_all: BOOL,
        new_state: *const TOKEN_PRIVILEGES,
        buffer_length: DWORD,
        previous_state: *mut c_void,
        return_length: *mut DWORD,
    ) -> BOOL;

    fn CloseHandle(handle: HANDLE) -> BOOL;
}

// =============================================================================
// Privilege enablement
// =============================================================================

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn enable_privilege(name: &str) -> bool {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            eprintln!("[-] OpenProcessToken failed: {}", std::io::Error::last_os_error());
            return false;
        }

        let wide_name = to_wide(name);
        let mut luid: LUID = 0;
        if LookupPrivilegeValueW(ptr::null(), wide_name.as_ptr(), &mut luid) == 0 {
            eprintln!("[-] LookupPrivilegeValue failed: {}", std::io::Error::last_os_error());
            CloseHandle(token);
            return false;
        }

        let tp = TOKEN_PRIVILEGES {
            privilege_count: 1,
            luid,
            attributes: SE_PRIVILEGE_ENABLED,
        };

        let ok = AdjustTokenPrivileges(
            token,
            0,
            &tp,
            mem::size_of::<TOKEN_PRIVILEGES>() as DWORD,
            ptr::null_mut(),
            ptr::null_mut(),
        );

        CloseHandle(token);

        if ok == 0 {
            eprintln!("[-] AdjustTokenPrivileges failed: {}", std::io::Error::last_os_error());
            return false;
        }

        true
    }
}

// =============================================================================
// Main
// =============================================================================

fn main() {
    println!("=== Superfetch PfnQuery Test ===");
    println!();

    // Step 1: Enable SeProfileSingleProcessPrivilege
    println!("[*] Enabling SeProfileSingleProcessPrivilege...");
    if !enable_privilege("SeProfileSingleProcessPrivilege") {
        println!("[-] FAILED to enable privilege. Run as Administrator.");
        std::process::exit(1);
    }
    println!("[+] Privilege enabled");

    // Step 2: Prepare output buffer for PFN ranges
    const MAX_RANGES: usize = 256;
    let mut ranges = vec![PF_PFN_RANGE { base_pfn: 0, count: 0 }; MAX_RANGES];
    let ranges_size = (MAX_RANGES * mem::size_of::<PF_PFN_RANGE>()) as u32;

    // Step 3: Build SuperfetchInformation struct
    let mut sfinfo = SUPERFETCH_INFORMATION {
        version: 45,
        magic: 0x43687546, // "FuhC" — required magic
        info_class: SUPERFETCH_PFN_QUERY,
        data: ranges.as_mut_ptr() as *mut c_void,
        data_length: ranges_size,
    };

    let input_size = mem::size_of::<SUPERFETCH_INFORMATION>() as u32;

    // Step 4: Call NtQuerySystemInformation
    println!("[*] Calling NtQuerySystemInformation(79) with info_class=17...");

    let mut return_length: u32 = 0;
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_SUPERFETCH_INFORMATION,
            &mut sfinfo as *mut _ as *mut c_void,
            input_size,
            &mut return_length,
        )
    };

    // Step 5: Report results
    println!();
    println!("--- Results ---");
    println!("  NTSTATUS:      0x{:08X} ({})", status as u32, ntstatus_name(status));
    println!("  Return length: {} bytes", return_length);

    if status == STATUS_SUCCESS {
        // Count how many ranges have non-zero data
        let num_ranges = ranges.iter().take_while(|r| r.count > 0).count();
        println!("  Ranges returned: {}", num_ranges);

        if num_ranges > 0 {
            println!();
            println!("  First 10 ranges:");
            for (i, r) in ranges.iter().take(10.min(num_ranges)).enumerate() {
                let base_phys = r.base_pfn * 0x1000;
                let size_mb = (r.count * 0x1000) as f64 / (1024.0 * 1024.0);
                println!(
                    "    [{:2}] PFN 0x{:08X} (phys 0x{:012X}), {} pages ({:.1} MB)",
                    i, r.base_pfn, base_phys, r.count, size_mb
                );
            }
        }

        println!();
        println!("[+] Superfetch PfnQuery is AVAILABLE on this build");
    } else {
        println!();
        println!("[-] Superfetch PfnQuery UNAVAILABLE or BLOCKED");
        println!("    This may indicate:");
        println!("    - Superfetch/SysMain service is disabled");
        println!("    - Windows version does not expose PFN data via this path");
        println!("    - Insufficient privileges");
    }
}

fn ntstatus_name(status: NTSTATUS) -> &'static str {
    const STATUS_PENDING: NTSTATUS = 0x00000103u32 as i32;
    const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004u32 as i32;
    const STATUS_ACCESS_DENIED: NTSTATUS = 0xC0000022u32 as i32;
    const STATUS_NOT_SUPPORTED: NTSTATUS = 0xC00000BBu32 as i32;
    const STATUS_INVALID_INFO_CLASS: NTSTATUS = 0xC0000003u32 as i32;

    match status {
        0x00000000 => "STATUS_SUCCESS",
        STATUS_PENDING => "STATUS_PENDING",
        STATUS_INFO_LENGTH_MISMATCH => "STATUS_INFO_LENGTH_MISMATCH",
        STATUS_ACCESS_DENIED => "STATUS_ACCESS_DENIED",
        STATUS_NOT_SUPPORTED => "STATUS_NOT_SUPPORTED",
        STATUS_INVALID_INFO_CLASS => "STATUS_INVALID_INFO_CLASS",
        _ => "UNKNOWN",
    }
}
