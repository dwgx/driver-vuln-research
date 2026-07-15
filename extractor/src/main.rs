//! extractor.exe — AES key extraction orchestrator
//!
//! Usage: extractor.exe [--driver lnvmsrio|corsair] [--target VRChat.exe] [--method ppl|physical]
//! Default: --driver lnvmsrio --target VRChat.exe --method ppl

mod drivers;
mod memory;
mod scan;

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use drivers::PhysicalMemoryDriver;
use memory::eprocess;
use scan::pattern::{scan_page_for_aes_schedule, AesKeyResult};

// =============================================================================
// IOCTL Safety Counter
// =============================================================================

static IOCTL_COUNT: AtomicU32 = AtomicU32::new(0);
const IOCTL_WARN_THRESHOLD: u32 = 80;
const IOCTL_HARD_LIMIT: u32 = 100;

fn ioctl_tick() -> io::Result<()> {
    let count = IOCTL_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    if count >= IOCTL_HARD_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("IOCTL hard limit reached ({}/{}). Aborting.", count, IOCTL_HARD_LIMIT),
        ));
    }
    if count == IOCTL_WARN_THRESHOLD {
        eprintln!("[!] WARNING: IOCTL count at {}/{}", count, IOCTL_HARD_LIMIT);
    }
    Ok(())
}

// =============================================================================
// CLI Parsing
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum DriverChoice {
    LnvMsrio,
    Corsair,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Method {
    Ppl,
    Physical,
}

struct Config {
    driver: DriverChoice,
    target: String,
    method: Method,
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut driver = DriverChoice::LnvMsrio;
    let mut target = String::from("VRChat.exe");
    let mut method = Method::Ppl;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--driver" => {
                i += 1;
                if i < args.len() {
                    driver = match args[i].to_lowercase().as_str() {
                        "corsair" => DriverChoice::Corsair,
                        _ => DriverChoice::LnvMsrio,
                    };
                }
            }
            "--target" => {
                i += 1;
                if i < args.len() {
                    target = args[i].clone();
                }
            }
            "--method" => {
                i += 1;
                if i < args.len() {
                    method = match args[i].to_lowercase().as_str() {
                        "physical" => Method::Physical,
                        _ => Method::Ppl,
                    };
                }
            }
            _ => {
                eprintln!("[!] Unknown argument: {}", args[i]);
            }
        }
        i += 1;
    }

    Config { driver, target, method }
}

// =============================================================================
// Windows API FFI (process memory access for PPL method)
// =============================================================================

#[cfg(target_os = "windows")]
mod winapi {
    use std::ffi::c_void;
    use std::io;

    type HANDLE = *mut c_void;
    type DWORD = u32;
    type BOOL = i32;
    type SIZE_T = usize;

    const PROCESS_VM_READ: DWORD = 0x0010;
    const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
    const MEM_COMMIT: DWORD = 0x1000;
    const PAGE_NOACCESS: DWORD = 0x01;
    const PAGE_GUARD: DWORD = 0x100;

    #[repr(C)]
    pub struct MemoryBasicInformation {
        pub base_address: *mut c_void,
        pub allocation_base: *mut c_void,
        pub allocation_protect: DWORD,
        pub region_size: SIZE_T,
        pub state: DWORD,
        pub protect: DWORD,
        pub mem_type: DWORD,
    }

    extern "system" {
        fn OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD) -> HANDLE;
        fn CloseHandle(handle: HANDLE) -> BOOL;
        fn VirtualQueryEx(
            process: HANDLE,
            address: *const c_void,
            buffer: *mut MemoryBasicInformation,
            length: SIZE_T,
        ) -> SIZE_T;
        fn ReadProcessMemory(
            process: HANDLE,
            base: *const c_void,
            buffer: *mut c_void,
            size: SIZE_T,
            bytes_read: *mut SIZE_T,
        ) -> BOOL;
    }

    pub struct ProcessHandle {
        handle: HANDLE,
    }

    impl ProcessHandle {
        pub fn open(pid: u32) -> io::Result<Self> {
            let handle = unsafe {
                OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid)
            };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { handle })
        }

        /// Enumerate committed, readable memory regions via VirtualQueryEx.
        pub fn enumerate_regions(&self) -> Vec<(usize, usize)> {
            let mut regions = Vec::new();
            let mut addr: usize = 0;

            loop {
                let mut mbi: MemoryBasicInformation = unsafe { std::mem::zeroed() };
                let ret = unsafe {
                    VirtualQueryEx(
                        self.handle,
                        addr as *const c_void,
                        &mut mbi,
                        std::mem::size_of::<MemoryBasicInformation>(),
                    )
                };
                if ret == 0 {
                    break;
                }

                let is_committed = mbi.state == MEM_COMMIT;
                let is_accessible = mbi.protect != PAGE_NOACCESS
                    && (mbi.protect & PAGE_GUARD) == 0;

                if is_committed && is_accessible && mbi.region_size > 0 {
                    regions.push((mbi.base_address as usize, mbi.region_size));
                }

                addr = (mbi.base_address as usize).saturating_add(mbi.region_size);
                if addr == 0 {
                    break;
                }
            }

            regions
        }

        /// Read a page (4096 bytes) from the target process.
        pub fn read_page(&self, address: usize) -> io::Result<Vec<u8>> {
            let mut buffer = vec![0u8; 4096];
            let mut bytes_read: SIZE_T = 0;
            let ret = unsafe {
                ReadProcessMemory(
                    self.handle,
                    address as *const c_void,
                    buffer.as_mut_ptr() as *mut c_void,
                    4096,
                    &mut bytes_read,
                )
            };
            if ret == 0 {
                return Err(io::Error::last_os_error());
            }
            buffer.truncate(bytes_read);
            Ok(buffer)
        }
    }

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe { CloseHandle(self.handle); }
            }
        }
    }
}

// =============================================================================
// Service Cleanup Guard
// =============================================================================

struct ServiceCleanup<'a> {
    scm: &'a drivers::service::ServiceManager,
    service_name: &'a str,
}

impl<'a> Drop for ServiceCleanup<'a> {
    fn drop(&mut self) {
        let _ = self.scm.stop(self.service_name);
        let _ = self.scm.delete(self.service_name);
    }
}

// =============================================================================
// Entry Point
// =============================================================================

fn main() {
    let config = parse_args();
    let start_time = Instant::now();

    println!("[*] extractor v0.1.0");
    println!("[*] Driver:  {:?}", config.driver);
    println!("[*] Target:  {}", config.target);
    println!("[*] Method:  {:?}", config.method);
    println!();

    let result = match config.method {
        Method::Ppl => run_ppl_pipeline(&config),
        Method::Physical => run_physical_pipeline(&config),
    };

    let elapsed = start_time.elapsed();
    println!();
    println!("[*] Total time: {:.2}s", elapsed.as_secs_f64());
    println!("[*] IOCTLs issued: {}", IOCTL_COUNT.load(Ordering::SeqCst));

    match result {
        Ok(keys) => {
            if keys.is_empty() {
                println!("[*] No AES-128 key schedules found.");
            } else {
                println!("[+] Found {} AES-128 key(s):", keys.len());
                for (i, key_result) in keys.iter().enumerate() {
                    let hex: String = key_result.key.iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    println!("    [{}] {} (confidence: {:.2}, offset: 0x{:X})",
                        i + 1, hex, key_result.confidence, key_result.offset);
                }
            }
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[-] FATAL: {}", e);
            std::process::exit(1);
        }
    }
}

// =============================================================================
// PPL Bypass Pipeline
// =============================================================================

fn run_ppl_pipeline(config: &Config) -> io::Result<Vec<AesKeyResult>> {
    // Step 1: Load driver via ServiceManager
    println!("[1/9] Loading driver...");
    let scm = drivers::service::ServiceManager::connect()?;

    let (service_name, driver_path) = match config.driver {
        DriverChoice::LnvMsrio => ("LnvMSRIO", "C:\\Windows\\System32\\drivers\\LnvMSRIO.sys"),
        DriverChoice::Corsair => ("CorsairLLAccess", "C:\\Windows\\System32\\drivers\\CorsairLLAccess64.sys"),
    };

    // Try to create; ignore error if already exists (ERROR_SERVICE_EXISTS = 1073)
    match scm.create(service_name, driver_path) {
        Ok(()) => println!("    Service created: {}", service_name),
        Err(ref e) if e.raw_os_error() == Some(1073) => {
            println!("    Service already exists: {}", service_name);
        }
        Err(e) => return Err(e),
    }

    match scm.start(service_name) {
        Ok(()) => println!("    Service started"),
        Err(ref e) if e.raw_os_error() == Some(1056) => {
            // ERROR_SERVICE_ALREADY_RUNNING
            println!("    Service already running");
        }
        Err(e) => return Err(e),
    }

    // Cleanup guard: stop + delete on any exit path
    let _cleanup = ServiceCleanup { scm: &scm, service_name };

    // Open the driver handle
    let driver = drivers::lnvmsrio::LnvMsrioDriver::open()?;
    ioctl_tick()?;
    println!("    Driver handle acquired");

    // Step 2: Find target EPROCESS
    println!("[2/9] Locating EPROCESS for '{}'...", config.target);
    let system_eprocess = find_initial_eprocess(&driver)?;
    ioctl_tick()?;

    let target_eprocess = eprocess::find_eprocess_by_name(
        &driver, system_eprocess, &config.target
    )?;
    ioctl_tick()?;
    println!("    Target EPROCESS: 0x{:X}", target_eprocess);

    // Read PID from EPROCESS
    let pid = {
        let reader = memory::physical::SafePhysicalReader::new(&driver);
        reader.read_u64_safe(target_eprocess + eprocess::EPROCESS_PID)?
    };
    ioctl_tick()?;
    println!("    Target PID: {}", pid);

    // Step 3: Clear PPL protection
    println!("[3/9] Clearing PPL protection...");
    eprocess::clear_ppl(&driver, target_eprocess)?;
    ioctl_tick()?;
    println!("    PPL byte zeroed at EPROCESS+0x{:X}", eprocess::EPROCESS_PROTECTION);

    // Step 4: OpenProcess with PROCESS_VM_READ
    println!("[4/9] Opening process handle (PID {})...", pid);
    #[cfg(target_os = "windows")]
    let proc_handle = winapi::ProcessHandle::open(pid as u32)?;
    #[cfg(not(target_os = "windows"))]
    return Err(io::Error::new(io::ErrorKind::Unsupported, "PPL method requires Windows"));

    println!("    Process handle acquired");

    // Step 5: Enumerate committed heap regions
    println!("[5/9] Enumerating memory regions...");
    #[cfg(target_os = "windows")]
    let regions = proc_handle.enumerate_regions();
    #[cfg(not(target_os = "windows"))]
    let regions: Vec<(usize, usize)> = Vec::new();

    let total_bytes: usize = regions.iter().map(|(_, sz)| *sz).sum();
    println!("    {} regions, {:.1} MB total",
        regions.len(), total_bytes as f64 / (1024.0 * 1024.0));

    // Step 6-7: Read pages and scan for AES key schedules
    println!("[6/9] Scanning memory for AES-128 key schedules...");
    let mut all_keys: Vec<AesKeyResult> = Vec::new();
    let mut pages_scanned: u64 = 0;
    let mut read_errors: u64 = 0;

    for (base, size) in &regions {
        let page_count = size / 4096;
        for page_idx in 0..page_count {
            let addr = base + page_idx * 4096;

            #[cfg(target_os = "windows")]
            let page_result = proc_handle.read_page(addr);
            #[cfg(not(target_os = "windows"))]
            let page_result: io::Result<Vec<u8>> = Err(io::Error::new(
                io::ErrorKind::Unsupported, "not windows"
            ));

            match page_result {
                Ok(page_data) => {
                    let hits = scan_page_for_aes_schedule(&page_data);
                    for mut hit in hits {
                        // Adjust offset to be absolute virtual address
                        hit.offset += addr;
                        all_keys.push(hit);
                    }
                }
                Err(_) => {
                    read_errors += 1;
                }
            }
            pages_scanned += 1;

            // Progress every 10000 pages
            if pages_scanned % 10000 == 0 {
                print!("\r    Scanned {} pages ({} errors)...",
                    pages_scanned, read_errors);
            }
        }
    }
    println!("\r    Scanned {} pages, {} read errors        ", pages_scanned, read_errors);

    // Step 8: Report
    println!("[7/9] Scan complete.");

    // Deduplicate keys (same 16-byte key found at multiple offsets)
    all_keys.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    dedup_keys(&mut all_keys);

    // Step 9: Cleanup handled by Drop impls
    println!("[8/9] Cleanup (Drop guards active)...");
    println!("[9/9] Done.");

    Ok(all_keys)
}

// =============================================================================
// Physical Scan Pipeline (fallback)
// =============================================================================

fn run_physical_pipeline(config: &Config) -> io::Result<Vec<AesKeyResult>> {
    // Step 1: Load driver (same as PPL)
    println!("[1/6] Loading driver...");
    let scm = drivers::service::ServiceManager::connect()?;

    let (service_name, driver_path) = match config.driver {
        DriverChoice::LnvMsrio => ("LnvMSRIO", "C:\\Windows\\System32\\drivers\\LnvMSRIO.sys"),
        DriverChoice::Corsair => ("CorsairLLAccess", "C:\\Windows\\System32\\drivers\\CorsairLLAccess64.sys"),
    };

    match scm.create(service_name, driver_path) {
        Ok(()) => println!("    Service created: {}", service_name),
        Err(ref e) if e.raw_os_error() == Some(1073) => {
            println!("    Service already exists: {}", service_name);
        }
        Err(e) => return Err(e),
    }

    match scm.start(service_name) {
        Ok(()) => println!("    Service started"),
        Err(ref e) if e.raw_os_error() == Some(1056) => {
            println!("    Service already running");
        }
        Err(e) => return Err(e),
    }

    let _cleanup = ServiceCleanup { scm: &scm, service_name };
    let driver = drivers::lnvmsrio::LnvMsrioDriver::open()?;
    ioctl_tick()?;
    println!("    Driver handle acquired");

    // Step 2: Find target EPROCESS
    println!("[2/6] Locating EPROCESS for '{}'...", config.target);
    let system_eprocess = find_initial_eprocess(&driver)?;
    ioctl_tick()?;

    let target_eprocess = eprocess::find_eprocess_by_name(
        &driver, system_eprocess, &config.target
    )?;
    ioctl_tick()?;
    println!("    Target EPROCESS: 0x{:X}", target_eprocess);

    // Step 3: Read CR3 from EPROCESS
    println!("[3/6] Reading CR3 (DirectoryTableBase)...");
    let cr3 = eprocess::read_cr3(&driver, target_eprocess)?;
    ioctl_tick()?;
    println!("    CR3: 0x{:X}", cr3);

    // Step 4: Walk page tables and scan physical pages
    // We scan a range of physical addresses directly since we cannot trivially
    // enumerate the process's virtual address space without Superfetch/MmCopyVirtualMemory.
    println!("[4/6] Physical scan via page table walk...");
    println!("    Scanning physical pages belonging to process...");

    let mut all_keys: Vec<AesKeyResult> = Vec::new();
    let mut pages_scanned: u64 = 0;

    // Walk PML4 entries from CR3
    let pml4_base = cr3 & 0xFFFF_FFFF_FFFF_F000;
    for pml4_idx in 0..512u64 {
        ioctl_tick()?;
        let pml4e = driver.read_physical_u64(pml4_base + pml4_idx * 8)?;

        // Skip non-present entries
        if pml4e & 1 == 0 {
            continue;
        }

        let pdpt_base = pml4e & 0xFFFF_FFFF_FFFF_F000;

        // Only scan user-space entries (indices 0..256 = lower-half)
        if pml4_idx >= 256 {
            break;
        }

        // Sample first PDPT entry to limit IOCTL usage
        ioctl_tick()?;
        let pdpte = driver.read_physical_u64(pdpt_base)?;
        if pdpte & 1 == 0 {
            continue;
        }

        // 1GB page?
        if pdpte & 0x80 != 0 {
            // Too large to scan efficiently; skip
            continue;
        }

        let pd_base = pdpte & 0xFFFF_FFFF_FFFF_F000;

        // Sample a few PD entries
        for pd_idx in 0..8u64 {
            if IOCTL_COUNT.load(Ordering::SeqCst) >= IOCTL_WARN_THRESHOLD {
                println!("\n    [!] Approaching IOCTL limit, stopping scan early");
                break;
            }

            ioctl_tick()?;
            let pde = driver.read_physical_u64(pd_base + pd_idx * 8)?;
            if pde & 1 == 0 {
                continue;
            }

            // 2MB page
            if pde & 0x80 != 0 {
                let phys_2m = pde & 0xFFFF_FFFF_FFE0_0000;
                // Read first page of the 2MB region
                ioctl_tick()?;
                match driver.read_physical(phys_2m, 4096) {
                    Ok(page_data) => {
                        let hits = scan_page_for_aes_schedule(&page_data);
                        for mut hit in hits {
                            hit.offset += phys_2m as usize;
                            all_keys.push(hit);
                        }
                        pages_scanned += 1;
                    }
                    Err(_) => {}
                }
                continue;
            }

            // 4KB pages: read page table
            let pt_base = pde & 0xFFFF_FFFF_FFFF_F000;
            ioctl_tick()?;
            let pte = driver.read_physical_u64(pt_base)?;
            if pte & 1 == 0 {
                continue;
            }

            let phys_page = pte & 0xFFFF_FFFF_FFFF_F000;
            ioctl_tick()?;
            match driver.read_physical(phys_page, 4096) {
                Ok(page_data) => {
                    let hits = scan_page_for_aes_schedule(&page_data);
                    for mut hit in hits {
                        hit.offset += phys_page as usize;
                        all_keys.push(hit);
                    }
                    pages_scanned += 1;
                }
                Err(_) => {}
            }
        }
    }

    println!("    Physical pages scanned: {}", pages_scanned);

    // Step 5: Report
    println!("[5/6] Scan complete.");
    all_keys.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    dedup_keys(&mut all_keys);

    // Step 6: Cleanup via Drop
    println!("[6/6] Cleanup.");

    Ok(all_keys)
}

// =============================================================================
// Helpers
// =============================================================================

/// Bootstrap: find System EPROCESS (PID 4) as the starting point for list walks.
/// Uses a known physical address heuristic for the idle/system process on Win11.
fn find_initial_eprocess(driver: &dyn PhysicalMemoryDriver) -> io::Result<u64> {
    // Strategy: scan a range of physical memory for the System process signature.
    // The EPROCESS for PID 4 is typically in the first 32MB of physical RAM.
    // We look for the ImageFileName "System\0" at the known offset.
    let reader = memory::physical::SafePhysicalReader::new(driver);

    // Scan in page increments through low physical memory
    let scan_end = 0x200_0000u64; // 32 MB
    let mut addr = 0x100000u64;   // Start at 1 MB

    while addr < scan_end {
        ioctl_tick()?;
        match reader.read_bytes_safe(addr + eprocess::EPROCESS_IMAGE_NAME, 7) {
            Ok(name_bytes) => {
                if &name_bytes == b"System\0" {
                    // Verify PID == 4
                    if let Ok(pid) = reader.read_u64_safe(addr + eprocess::EPROCESS_PID) {
                        if pid == 4 {
                            return Ok(addr);
                        }
                    }
                }
            }
            Err(_) => {}
        }
        addr += 0x1000; // Next page
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Could not locate System EPROCESS in physical memory",
    ))
}

/// Remove duplicate keys (same 16-byte value), keeping highest confidence.
fn dedup_keys(keys: &mut Vec<AesKeyResult>) {
    let mut seen: Vec<[u8; 16]> = Vec::new();
    keys.retain(|k| {
        if seen.contains(&k.key) {
            false
        } else {
            seen.push(k.key);
            true
        }
    });
}
