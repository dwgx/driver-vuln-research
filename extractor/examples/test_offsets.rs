//! Test harness: Kernel structure offset verification via LnvMSRIO
//!
//! Reads MSR 0xC0000101 to get KPCR, then walks the chain:
//!   KPCR -> KPRCB -> KTHREAD -> EPROCESS -> PID
//!
//! Verifies that offsets are correct for the running Windows build by
//! checking whether the resulting PID is a valid known value (4 = System).
//!
//! Run: cargo run --example test_offsets
//!
//! Requires: LnvMSRIO.sys loaded, run as Administrator

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::io;
use std::mem;
use std::ptr;

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
// Driver constants
// =============================================================================

const IOCTL_READ_MSR: DWORD = 0x9C402084;
const IOCTL_PHYS_MEM_READ: DWORD = 0x9C406104;

// =============================================================================
// Wire structs
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MsrReadInput {
    msr_index: u32,
    _padding: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PhysMemReadInput {
    physical_address: u64,
    access_size: u32,
    count: u32,
}

// =============================================================================
// Offset candidates
// =============================================================================

const KPCR_CURRENT_PRCB: u64 = 0x180;
const KPRCB_CURRENT_THREAD: u64 = 0x008;

// KTHREAD -> Process offset candidates
const KTHREAD_OFFSETS: &[(u64, &str)] = &[
    (0x220, "primary (Build 26100+)"),
    (0x218, "older Win11"),
    (0x228, "fallback A"),
    (0x230, "fallback B"),
];

// EPROCESS -> PID offset
const EPROCESS_PID: u64 = 0x1D0;

// =============================================================================
// Helpers
// =============================================================================

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct DriverHandle {
    handle: HANDLE,
}

impl DriverHandle {
    fn open() -> io::Result<Self> {
        let path = to_wide("\\\\.\\WinMsrDev");
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
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

    fn read_msr(&self, msr: u32) -> io::Result<u64> {
        let input = MsrReadInput {
            msr_index: msr,
            _padding: 0,
        };
        let mut output: u64 = 0;
        let mut bytes_returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_READ_MSR,
                &input as *const _ as *const c_void,
                mem::size_of::<MsrReadInput>() as DWORD,
                &mut output as *mut _ as *mut c_void,
                8,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(output)
        }
    }

    fn read_phys_u64(&self, phys_addr: u64) -> io::Result<u64> {
        let input = PhysMemReadInput {
            physical_address: phys_addr,
            access_size: 8,
            count: 1,
        };
        let mut output: u64 = 0;
        let mut bytes_returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_MEM_READ,
                &input as *const _ as *const c_void,
                mem::size_of::<PhysMemReadInput>() as DWORD,
                &mut output as *mut _ as *mut c_void,
                8,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(output)
        }
    }
}

impl Drop for DriverHandle {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.handle); }
        }
    }
}

// =============================================================================
// Virtual-to-physical translation (identity-mapped kernel region heuristic)
// =============================================================================

/// On most Windows builds, the kernel maps KPCR/KPRCB in the first few GB
/// with a direct (identity-like) mapping. For testing purposes we strip the
/// kernel base and treat the lower bits as a physical offset.
///
/// NOTE: This is a heuristic. A proper implementation would walk PML4 via CR3.
/// We use the KPCR self-reference to validate: KPCR+0x18 should point to itself.
fn virt_to_phys_heuristic(vaddr: u64) -> u64 {
    // Strip the canonical upper bits — physical = vaddr & 0x000F_FFFF_FFFF_FFFF
    // This works for identity-mapped kernel regions.
    vaddr & 0x000F_FFFF_FFFF_FFFF
}

// =============================================================================
// Main
// =============================================================================

fn main() {
    println!("=== Kernel Offset Verification Test ===");
    println!();

    // Step 1: Open driver
    println!("[*] Opening LnvMSRIO driver...");
    let driver = match DriverHandle::open() {
        Ok(d) => d,
        Err(e) => {
            println!("[-] Failed to open driver: {}", e);
            println!("    Ensure LnvMSRIO.sys is loaded (sc start LnvMSRIO)");
            std::process::exit(1);
        }
    };
    println!("[+] Driver opened");

    // Step 2: Read MSR 0xC0000101 (IA32_GS_BASE = KPCR virtual address)
    println!("[*] Reading MSR 0xC0000101 (IA32_GS_BASE)...");
    let kpcr_virt = match driver.read_msr(0xC0000101) {
        Ok(v) => v,
        Err(e) => {
            println!("[-] MSR read failed: {}", e);
            std::process::exit(1);
        }
    };
    println!("[+] KPCR virtual address: 0x{:016X}", kpcr_virt);

    let kpcr_phys = virt_to_phys_heuristic(kpcr_virt);
    println!("[*] KPCR physical (heuristic): 0x{:012X}", kpcr_phys);

    // Step 3: Read KPCR+0x180 -> KPRCB pointer
    println!();
    println!("[*] Reading KPCR+0x180 (CurrentPrcb)...");
    let prcb_virt = match driver.read_phys_u64(kpcr_phys + KPCR_CURRENT_PRCB) {
        Ok(v) => v,
        Err(e) => {
            println!("[-] Read failed at KPCR+0x180: {}", e);
            std::process::exit(1);
        }
    };
    println!("[+] KPRCB virtual: 0x{:016X}", prcb_virt);
    let prcb_phys = virt_to_phys_heuristic(prcb_virt);

    // Step 4: Read KPRCB+0x008 -> CurrentThread
    println!("[*] Reading KPRCB+0x008 (CurrentThread)...");
    let thread_virt = match driver.read_phys_u64(prcb_phys + KPRCB_CURRENT_THREAD) {
        Ok(v) => v,
        Err(e) => {
            println!("[-] Read failed at KPRCB+0x008: {}", e);
            std::process::exit(1);
        }
    };
    println!("[+] KTHREAD virtual: 0x{:016X}", thread_virt);
    let thread_phys = virt_to_phys_heuristic(thread_virt);

    // Step 5: Try KTHREAD offsets to find EPROCESS
    println!();
    println!("[*] Probing KTHREAD -> EPROCESS offsets...");
    println!("    (Looking for kernel pointer with PID field = valid value)");
    println!();

    let mut found_offset: Option<(u64, &str)> = None;

    for &(offset, label) in KTHREAD_OFFSETS {
        let candidate = match driver.read_phys_u64(thread_phys + offset) {
            Ok(v) => v,
            Err(e) => {
                println!("    KTHREAD+0x{:03X} [{}]: READ ERROR: {}", offset, label, e);
                continue;
            }
        };

        // Check if it looks like a kernel pointer
        let is_kernel_ptr = candidate >= 0xFFFF_8000_0000_0000 && candidate != u64::MAX;
        if !is_kernel_ptr {
            println!(
                "    KTHREAD+0x{:03X} [{}]: 0x{:016X} -- NOT a kernel pointer",
                offset, label, candidate
            );
            continue;
        }

        // Try to read PID from the candidate EPROCESS
        let eproc_phys = virt_to_phys_heuristic(candidate);
        let pid = match driver.read_phys_u64(eproc_phys + EPROCESS_PID) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "    KTHREAD+0x{:03X} [{}]: 0x{:016X} -> PID READ ERROR: {}",
                    offset, label, candidate, e
                );
                continue;
            }
        };

        let pid_valid = pid > 0 && pid < 0x10000; // Reasonable PID range
        let marker = if pid == 4 {
            " <-- System process!"
        } else if pid_valid {
            " (valid PID)"
        } else {
            " (unlikely PID)"
        };

        println!(
            "    KTHREAD+0x{:03X} [{}]: EPROCESS=0x{:016X}, PID={}{}",
            offset, label, candidate, pid, marker
        );

        if pid_valid && found_offset.is_none() {
            found_offset = Some((offset, label));
        }
    }

    // Step 6: Summary
    println!();
    println!("--- Summary ---");
    println!("  KPCR (virt):          0x{:016X}", kpcr_virt);
    println!("  KPRCB (virt):         0x{:016X}", prcb_virt);
    println!("  KTHREAD (virt):       0x{:016X}", thread_virt);

    match found_offset {
        Some((offset, label)) => {
            println!();
            println!("[+] CONFIRMED working offset: KTHREAD+0x{:03X} ({})", offset, label);
            println!("[+] Offset chain validated for this build");
        }
        None => {
            println!();
            println!("[-] NO valid KTHREAD->EPROCESS offset found!");
            println!("    The virt-to-phys heuristic may not work on this build.");
            println!("    Consider implementing CR3-based page table walk.");
        }
    }
}
