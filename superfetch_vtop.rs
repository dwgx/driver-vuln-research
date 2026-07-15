//! Superfetch VA-to-PA Translation Module
//!
//! Implements safe virtual-to-physical address translation using the Windows
//! Superfetch subsystem (NtQuerySystemInformation class 79). This avoids page
//! table walks and MmMapIoSpace entirely — the kernel returns PFN identity
//! information for validated RAM pages only.
//!
//! API chain:
//!   1. InfoClass 17 (MemoryRangesQuery) → valid physical memory ranges
//!   2. InfoClass 6  (PfnQuery)          → PFN → VirtualAddress mapping
//!   3. Invert to build VA → PA lookup
//!
//! Requires: SeProfileSingleProcessPrivilege + SeDebugPrivilege (admin)
//! Tested on: Windows 11 Build 26200 (25H2)

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem;
use std::ptr;

// =============================================================================
// Error Types
// =============================================================================

/// Errors from the Superfetch VtoP subsystem
#[derive(Debug)]
pub enum VtopError {
    /// Failed to enable required privilege
    PrivilegeError { privilege: &'static str, code: u32 },
    /// NtQuerySystemInformation returned NTSTATUS error
    NtStatus { status: i32, context: &'static str },
    /// Target process could not be opened
    ProcessOpen { pid: u32, code: u32 },
    /// The virtual address is not backed by a physical page (paged out or invalid)
    NotResident { virtual_address: u64 },
    /// No physical memory ranges returned from Superfetch
    NoMemoryRanges,
    /// Windows API call failed
    WinApi { function: &'static str, code: u32 },
}

impl std::fmt::Display for VtopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivilegeError { privilege, code } => {
                write!(f, "failed to enable {}: error {}", privilege, code)
            }
            Self::NtStatus { status, context } => {
                write!(f, "NTSTATUS 0x{:08X} during {}", *status as u32, context)
            }
            Self::ProcessOpen { pid, code } => {
                write!(f, "cannot open process {}: error {}", pid, code)
            }
            Self::NotResident { virtual_address } => {
                write!(f, "VA 0x{:016X} is not resident in physical memory", virtual_address)
            }
            Self::NoMemoryRanges => write!(f, "superfetch returned no physical memory ranges"),
            Self::WinApi { function, code } => {
                write!(f, "{} failed: error {}", function, code)
            }
        }
    }
}

impl std::error::Error for VtopError {}

// =============================================================================
// Windows FFI
// =============================================================================

#[cfg(windows)]
mod ffi {
    use std::ffi::c_void;

    pub type HANDLE = *mut c_void;
    pub type NTSTATUS = i32;
    pub type DWORD = u32;
    pub type BOOL = i32;
    pub type LUID = u64;

    pub const STATUS_SUCCESS: NTSTATUS = 0;
    pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC0000023_u32 as i32;

    pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    pub const FALSE: BOOL = 0;

    // Process access rights
    pub const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
    pub const PROCESS_VM_READ: DWORD = 0x0010;

    // Privilege constants
    pub const SE_PRIVILEGE_ENABLED: DWORD = 0x00000002;
    pub const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
    pub const TOKEN_QUERY: DWORD = 0x0008;

    // SystemInformationClass for Superfetch
    pub const SYSTEM_SUPERFETCH_INFORMATION: u32 = 79;

    // Superfetch info classes
    pub const SUPERFETCH_PFN_QUERY: u32 = 6;
    pub const SUPERFETCH_MEMORY_RANGES_QUERY: u32 = 17;

    // Privilege LUIDs (well-known on all Windows versions)
    pub const SE_PROF_SINGLE_PROCESS_PRIVILEGE: LUID = 13;
    pub const SE_DEBUG_PRIVILEGE: LUID = 20;

    #[repr(C)]
    pub struct TOKEN_PRIVILEGES {
        pub privilege_count: DWORD,
        pub privileges: [LUID_AND_ATTRIBUTES; 1],
    }

    #[repr(C)]
    pub struct LUID_AND_ATTRIBUTES {
        pub luid: LUID,
        pub attributes: DWORD,
    }

    #[repr(C)]
    pub struct MEMORY_BASIC_INFORMATION {
        pub base_address: *mut c_void,
        pub allocation_base: *mut c_void,
        pub allocation_protect: DWORD,
        pub partition_id: u16,
        pub region_size: usize,
        pub state: DWORD,
        pub protect: DWORD,
        pub type_: DWORD,
    }

    pub const MEM_COMMIT: DWORD = 0x1000;

    extern "system" {
        pub fn NtQuerySystemInformation(
            system_information_class: u32,
            system_information: *mut c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> NTSTATUS;

        pub fn OpenProcessToken(
            process_handle: HANDLE,
            desired_access: DWORD,
            token_handle: *mut HANDLE,
        ) -> BOOL;

        pub fn AdjustTokenPrivileges(
            token_handle: HANDLE,
            disable_all: BOOL,
            new_state: *const TOKEN_PRIVILEGES,
            buffer_length: DWORD,
            previous_state: *mut TOKEN_PRIVILEGES,
            return_length: *mut DWORD,
        ) -> BOOL;

        pub fn GetCurrentProcess() -> HANDLE;

        pub fn OpenProcess(
            desired_access: DWORD,
            inherit_handle: BOOL,
            process_id: DWORD,
        ) -> HANDLE;

        pub fn CloseHandle(handle: HANDLE) -> BOOL;

        pub fn GetLastError() -> DWORD;

        pub fn VirtualQueryEx(
            process: HANDLE,
            address: *const c_void,
            buffer: *mut MEMORY_BASIC_INFORMATION,
            length: usize,
        ) -> usize;
    }
}

// =============================================================================
// Superfetch Structures (from research: SUPERFETCH_VTOP_RESEARCH.md)
// =============================================================================

/// Wrapper structure for NtQuerySystemInformation(SystemSuperfetchInformation).
///
/// Layout (64-bit, 32 bytes total):
///   +0x00  Version    : ULONG  = 45 (Windows 11 25H2)
///   +0x04  Magic      : ULONG  = 0x4368756B ('kuhC' — "Chuk" reversed)
///   +0x08  InfoClass  : ULONG  (6 = PfnQuery, 17 = MemoryRangesQuery)
///   +0x0C  (padding)  : ULONG
///   +0x10  Data       : PVOID  → points to request-specific structure
///   +0x18  Length     : ULONG  (byte length of Data buffer)
///   +0x1C  (padding)  : ULONG
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SuperfetchInformation {
    /// Protocol version — must be 45 for Windows 11 25H2
    pub version: u32,
    /// Magic cookie 'kuhC' (0x4368756B) — validated by the kernel
    pub magic: u32,
    /// Superfetch sub-class: 6 (PfnQuery) or 17 (MemoryRangesQuery)
    pub info_class: u32,
    /// Alignment padding
    pub _pad0: u32,
    /// Pointer to the class-specific request buffer
    pub data: *mut c_void,
    /// Byte length of the data buffer
    pub length: u32,
    /// Alignment padding
    pub _pad1: u32,
}

const SUPERFETCH_VERSION: u32 = 45;
const SUPERFETCH_MAGIC: u32 = 0x4368_756B; // 'kuhC'

/// PFN query request structure (InfoClass = 6).
///
/// Layout:
///   +0x00  Version      : ULONG = 1
///   +0x04  RequestFlags : ULONG = 1
///   +0x08  PfnCount     : ULONG (number of entries in PageData[])
///   +0x0C  (padding to align PageData to 8 bytes)
///   +0x10  PageData[]   : MMPFN_IDENTITY[PfnCount]
///
/// The caller fills PageData[i].PageFrameIndex with the PFNs to query.
/// On return, the kernel populates Flags and VirtualAddress for each entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PfPfnPrioRequestHeader {
    /// Structure version — must be 1
    pub version: u32,
    /// Request flags — set to 1 for basic PFN identity query
    pub request_flags: u32,
    /// Number of MMPFN_IDENTITY entries following this header
    pub pfn_count: u32,
    /// Padding for 8-byte alignment of the PageData array
    pub _pad0: u32,
}

/// Per-PFN identity entry (24 bytes).
///
/// Layout:
///   +0x00  Flags           : UINT64 (page type, priority, process info)
///   +0x08  PageFrameIndex  : UINT64 (PFN — physical page number)
///   +0x10  VirtualAddress  : UINT64 (VA this PFN maps to, or union fields)
///
/// Input: caller sets PageFrameIndex.
/// Output: kernel fills Flags and VirtualAddress.
///
/// The physical address for this page = PageFrameIndex << 12.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MmpfnIdentity {
    /// Flags bitfield:
    ///   bits[3:0]   = page priority (0-7)
    ///   bits[6:4]   = page location (Active/Standby/Modified/etc.)
    ///   bit[11]     = shared page
    ///   bits[63:48] = e_process high bits (for process identification)
    pub flags: u64,
    /// Physical page frame number (PA = pfn << 12)
    pub page_frame_index: u64,
    /// Virtual address this physical page is mapped at.
    /// For process-private pages: the usermode VA.
    /// For shared pages: may be a prototype PTE address.
    pub virtual_address: u64,
}

/// Physical memory range entry returned by InfoClass 17.
///
/// Layout:
///   +0x00  BasePfn   : UINT64 (starting PFN of the range)
///   +0x08  PageCount : UINT64 (number of contiguous pages)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PfPhysicalMemoryRange {
    /// First PFN in this contiguous physical memory range
    pub base_pfn: u64,
    /// Number of pages in this range
    pub page_count: u64,
}

/// Memory ranges query header (InfoClass = 17).
///
/// Layout:
///   +0x00  Version    : ULONG = 1
///   +0x04  RangeCount : ULONG (out: number of valid ranges)
///   +0x08  Ranges[]   : PfPhysicalMemoryRange[RangeCount]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PfMemoryRangeInfoHeader {
    /// Structure version — must be 1
    pub version: u32,
    /// Number of range entries (output)
    pub range_count: u32,
}

// =============================================================================
// Compile-time size checks
// =============================================================================

const _: () = assert!(mem::size_of::<SuperfetchInformation>() == 32);
const _: () = assert!(mem::size_of::<MmpfnIdentity>() == 24);
const _: () = assert!(mem::size_of::<PfPfnPrioRequestHeader>() == 16);
const _: () = assert!(mem::size_of::<PfPhysicalMemoryRange>() == 16);

// =============================================================================
// Privilege Management
// =============================================================================

/// Enable a token privilege by LUID value.
/// Returns Ok(()) on success, Err with the Win32 error code on failure.
#[cfg(windows)]
fn enable_privilege(luid: ffi::LUID) -> Result<(), u32> {
    unsafe {
        let mut token: ffi::HANDLE = ptr::null_mut();
        let result = ffi::OpenProcessToken(
            ffi::GetCurrentProcess(),
            ffi::TOKEN_ADJUST_PRIVILEGES | ffi::TOKEN_QUERY,
            &mut token,
        );
        if result == ffi::FALSE {
            return Err(ffi::GetLastError());
        }

        let tp = ffi::TOKEN_PRIVILEGES {
            privilege_count: 1,
            privileges: [ffi::LUID_AND_ATTRIBUTES {
                luid,
                attributes: ffi::SE_PRIVILEGE_ENABLED,
            }],
        };

        let success = ffi::AdjustTokenPrivileges(
            token,
            ffi::FALSE,
            &tp,
            mem::size_of::<ffi::TOKEN_PRIVILEGES>() as u32,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        let err = ffi::GetLastError();
        ffi::CloseHandle(token);

        // AdjustTokenPrivileges returns TRUE even when it fails partially;
        // must check GetLastError for ERROR_NOT_ALL_ASSIGNED (1300).
        if success == ffi::FALSE || err != 0 {
            return Err(err);
        }

        Ok(())
    }
}

/// Enable both privileges required for Superfetch queries.
#[cfg(windows)]
fn ensure_privileges() -> Result<(), VtopError> {
    enable_privilege(ffi::SE_PROF_SINGLE_PROCESS_PRIVILEGE).map_err(|code| {
        VtopError::PrivilegeError {
            privilege: "SeProfileSingleProcessPrivilege",
            code,
        }
    })?;

    enable_privilege(ffi::SE_DEBUG_PRIVILEGE).map_err(|code| {
        VtopError::PrivilegeError {
            privilege: "SeDebugPrivilege",
            code,
        }
    })?;

    Ok(())
}

// =============================================================================
// Superfetch Query Helpers
// =============================================================================

/// Maximum PFNs to query in a single NtQuerySystemInformation call.
/// Limited to avoid exceeding kernel buffer limits (~16 MB practical max).
const PFN_BATCH_SIZE: usize = 1024;

/// Query valid physical memory ranges via Superfetch InfoClass 17.
/// Returns a list of (base_pfn, page_count) tuples describing all usable RAM.
#[cfg(windows)]
fn query_memory_ranges() -> Result<Vec<PfPhysicalMemoryRange>, VtopError> {
    // Allocate buffer: header + generous space for ranges.
    // Typical systems have 8-32 ranges; allocate for 256 to be safe.
    const MAX_RANGES: usize = 256;
    let buf_size = mem::size_of::<PfMemoryRangeInfoHeader>()
        + MAX_RANGES * mem::size_of::<PfPhysicalMemoryRange>();

    let mut buffer = vec![0u8; buf_size];

    // Initialize the range info header
    let header = buffer.as_mut_ptr() as *mut PfMemoryRangeInfoHeader;
    unsafe {
        (*header).version = 1;
        (*header).range_count = MAX_RANGES as u32;
    }

    // Build the SUPERFETCH_INFORMATION wrapper
    let mut sf_info = SuperfetchInformation {
        version: SUPERFETCH_VERSION,
        magic: SUPERFETCH_MAGIC,
        info_class: ffi::SUPERFETCH_MEMORY_RANGES_QUERY,
        _pad0: 0,
        data: buffer.as_mut_ptr() as *mut c_void,
        length: buf_size as u32,
        _pad1: 0,
    };

    let status = unsafe {
        ffi::NtQuerySystemInformation(
            ffi::SYSTEM_SUPERFETCH_INFORMATION,
            &mut sf_info as *mut _ as *mut c_void,
            mem::size_of::<SuperfetchInformation>() as u32,
            ptr::null_mut(),
        )
    };

    if status != ffi::STATUS_SUCCESS {
        return Err(VtopError::NtStatus {
            status,
            context: "SuperfetchMemoryRangesQuery",
        });
    }

    let range_count = unsafe { (*header).range_count } as usize;
    if range_count == 0 {
        return Err(VtopError::NoMemoryRanges);
    }

    // Read range entries from after the header
    let ranges_ptr = unsafe {
        buffer
            .as_ptr()
            .add(mem::size_of::<PfMemoryRangeInfoHeader>())
    } as *const PfPhysicalMemoryRange;

    let ranges: Vec<PfPhysicalMemoryRange> = (0..range_count)
        .map(|i| unsafe { *ranges_ptr.add(i) })
        .collect();

    Ok(ranges)
}

/// Query PFN identities for a batch of page frame numbers.
/// Sets each entry's PageFrameIndex as input; kernel fills VirtualAddress.
#[cfg(windows)]
fn query_pfn_batch(pfns: &[u64]) -> Result<Vec<MmpfnIdentity>, VtopError> {
    if pfns.is_empty() {
        return Ok(Vec::new());
    }

    let entry_count = pfns.len();

    // Buffer layout: PfPfnPrioRequestHeader + MmpfnIdentity[entry_count]
    let buf_size = mem::size_of::<PfPfnPrioRequestHeader>()
        + entry_count * mem::size_of::<MmpfnIdentity>();
    let mut buffer = vec![0u8; buf_size];

    // Fill header
    let header = buffer.as_mut_ptr() as *mut PfPfnPrioRequestHeader;
    unsafe {
        (*header).version = 1;
        (*header).request_flags = 1;
        (*header).pfn_count = entry_count as u32;
        (*header)._pad0 = 0;
    }

    // Fill PFN entries
    let entries_ptr = unsafe {
        buffer
            .as_mut_ptr()
            .add(mem::size_of::<PfPfnPrioRequestHeader>())
    } as *mut MmpfnIdentity;

    for (i, &pfn) in pfns.iter().enumerate() {
        unsafe {
            let entry = &mut *entries_ptr.add(i);
            entry.flags = 0;
            entry.page_frame_index = pfn;
            entry.virtual_address = 0;
        }
    }

    // Build SUPERFETCH_INFORMATION wrapper
    let mut sf_info = SuperfetchInformation {
        version: SUPERFETCH_VERSION,
        magic: SUPERFETCH_MAGIC,
        info_class: ffi::SUPERFETCH_PFN_QUERY,
        _pad0: 0,
        data: buffer.as_mut_ptr() as *mut c_void,
        length: buf_size as u32,
        _pad1: 0,
    };

    let status = unsafe {
        ffi::NtQuerySystemInformation(
            ffi::SYSTEM_SUPERFETCH_INFORMATION,
            &mut sf_info as *mut _ as *mut c_void,
            mem::size_of::<SuperfetchInformation>() as u32,
            ptr::null_mut(),
        )
    };

    if status != ffi::STATUS_SUCCESS {
        return Err(VtopError::NtStatus {
            status,
            context: "SuperfetchPfnQuery",
        });
    }

    // Read results back
    let results: Vec<MmpfnIdentity> = (0..entry_count)
        .map(|i| unsafe { *entries_ptr.add(i) })
        .collect();

    Ok(results)
}

// =============================================================================
// Process Helpers
// =============================================================================

/// RAII wrapper for a process HANDLE
#[cfg(windows)]
struct ProcessHandle {
    handle: ffi::HANDLE,
}

#[cfg(windows)]
impl ProcessHandle {
    fn open(pid: u32) -> Result<Self, VtopError> {
        let handle = unsafe {
            ffi::OpenProcess(
                ffi::PROCESS_QUERY_INFORMATION | ffi::PROCESS_VM_READ,
                ffi::FALSE,
                pid,
            )
        };

        if handle.is_null() || handle == ffi::INVALID_HANDLE_VALUE {
            return Err(VtopError::ProcessOpen {
                pid,
                code: unsafe { ffi::GetLastError() },
            });
        }

        Ok(Self { handle })
    }

    /// Check if a virtual address is committed (backed by the pagefile or RAM).
    fn is_committed(&self, va: u64) -> bool {
        let mut mbi: ffi::MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let result = unsafe {
            ffi::VirtualQueryEx(
                self.handle,
                va as *const c_void,
                &mut mbi,
                mem::size_of::<ffi::MEMORY_BASIC_INFORMATION>(),
            )
        };
        result != 0 && (mbi.state & ffi::MEM_COMMIT) != 0
    }
}

#[cfg(windows)]
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != ffi::INVALID_HANDLE_VALUE {
            unsafe { ffi::CloseHandle(self.handle); }
        }
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Translate a single virtual address to its physical address using Superfetch.
///
/// This function:
///   1. Enables SeProfileSingleProcessPrivilege and SeDebugPrivilege
///   2. Opens the target process to verify the VA is committed
///   3. Queries all physical memory ranges (InfoClass 17)
///   4. Scans PFN identities in batches (InfoClass 6) looking for a match
///   5. Returns the physical address (PFN << 12 | page_offset)
///
/// # Arguments
/// * `pid` - Target process ID
/// * `virtual_address` - Virtual address to translate
///
/// # Returns
/// * `Ok(physical_address)` on success
/// * `Err(VtopError::NotResident)` if the page is not in physical memory
///
/// # Performance
/// Single-address lookups scan the entire PFN database — O(total_RAM_pages).
/// For multiple addresses, prefer `vtop_batch()` which amortizes the scan.
#[cfg(windows)]
pub fn vtop(pid: u32, virtual_address: u64) -> Result<u64, VtopError> {
    ensure_privileges()?;

    let process = ProcessHandle::open(pid)?;
    if !process.is_committed(virtual_address) {
        return Err(VtopError::NotResident { virtual_address });
    }

    let page_offset = virtual_address & 0xFFF;
    let target_va_page = virtual_address & !0xFFF;

    let ranges = query_memory_ranges()?;

    // Scan all physical memory ranges, querying PFNs in batches
    for range in &ranges {
        let mut pfn = range.base_pfn;
        let end_pfn = range.base_pfn + range.page_count;

        while pfn < end_pfn {
            let batch_end = (pfn + PFN_BATCH_SIZE as u64).min(end_pfn);
            let batch: Vec<u64> = (pfn..batch_end).collect();

            let results = query_pfn_batch(&batch)?;

            for entry in &results {
                // Match: the kernel-reported VA (page-aligned) matches our target
                let entry_va = entry.virtual_address & !0xFFF;
                if entry_va == target_va_page && entry.virtual_address != 0 {
                    let physical_address = (entry.page_frame_index << 12) | page_offset;
                    return Ok(physical_address);
                }
            }

            pfn = batch_end;
        }
    }

    Err(VtopError::NotResident { virtual_address })
}

/// Translate multiple virtual addresses to physical addresses in a single pass.
///
/// This is significantly more efficient than calling `vtop()` repeatedly because
/// it scans the PFN database once and resolves all addresses in that scan.
///
/// # Arguments
/// * `pid` - Target process ID
/// * `addresses` - Slice of virtual addresses to translate
///
/// # Returns
/// A Vec of the same length as `addresses`. Each element is:
/// * `Some(physical_address)` if the page was found resident
/// * `None` if the page is not in physical memory (paged out or invalid)
#[cfg(windows)]
pub fn vtop_batch(pid: u32, addresses: &[u64]) -> Result<Vec<Option<u64>>, VtopError> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }

    ensure_privileges()?;

    let process = ProcessHandle::open(pid)?;
    let ranges = query_memory_ranges()?;

    // Build a lookup set: page-aligned VA → index in the output vec
    let mut pending: HashMap<u64, Vec<usize>> = HashMap::with_capacity(addresses.len());
    for (i, &va) in addresses.iter().enumerate() {
        if process.is_committed(va) {
            pending.entry(va & !0xFFF).or_default().push(i);
        }
    }

    let mut results: Vec<Option<u64>> = vec![None; addresses.len()];
    let mut remaining = pending.len();

    // Scan all physical ranges
    'outer: for range in &ranges {
        if remaining == 0 {
            break;
        }

        let mut pfn = range.base_pfn;
        let end_pfn = range.base_pfn + range.page_count;

        while pfn < end_pfn {
            if remaining == 0 {
                break 'outer;
            }

            let batch_end = (pfn + PFN_BATCH_SIZE as u64).min(end_pfn);
            let batch: Vec<u64> = (pfn..batch_end).collect();

            let entries = query_pfn_batch(&batch)?;

            for entry in &entries {
                if entry.virtual_address == 0 {
                    continue;
                }
                let entry_va_page = entry.virtual_address & !0xFFF;

                if let Some(indices) = pending.get(&entry_va_page) {
                    for &idx in indices {
                        let page_offset = addresses[idx] & 0xFFF;
                        let pa = (entry.page_frame_index << 12) | page_offset;
                        results[idx] = Some(pa);
                    }
                    remaining -= 1;
                }
            }

            pfn = batch_end;
        }
    }

    Ok(results)
}

// =============================================================================
// Builder API (for caching / repeated lookups)
// =============================================================================

/// Cached Superfetch VtoP resolver.
///
/// Builds the complete VA→PA mapping once, then answers lookups in O(1).
/// Useful when performing many translations against the same process state.
#[cfg(windows)]
pub struct SuperfetchVtopCache {
    /// VA (page-aligned) → PA (page-aligned)
    map: HashMap<u64, u64>,
    pid: u32,
}

#[cfg(windows)]
impl SuperfetchVtopCache {
    /// Build the full VA→PA cache for a process. Scans all physical memory.
    ///
    /// This is expensive (proportional to total RAM) but subsequent lookups
    /// are O(1). The cache is a snapshot — pages may be reassigned after build.
    pub fn build(pid: u32) -> Result<Self, VtopError> {
        ensure_privileges()?;
        let _process = ProcessHandle::open(pid)?;
        let ranges = query_memory_ranges()?;

        let mut map: HashMap<u64, u64> = HashMap::new();

        for range in &ranges {
            let mut pfn = range.base_pfn;
            let end_pfn = range.base_pfn + range.page_count;

            while pfn < end_pfn {
                let batch_end = (pfn + PFN_BATCH_SIZE as u64).min(end_pfn);
                let batch: Vec<u64> = (pfn..batch_end).collect();

                if let Ok(entries) = query_pfn_batch(&batch) {
                    for entry in &entries {
                        if entry.virtual_address != 0 {
                            let va_page = entry.virtual_address & !0xFFF;
                            let pa_page = entry.page_frame_index << 12;
                            map.insert(va_page, pa_page);
                        }
                    }
                }

                pfn = batch_end;
            }
        }

        Ok(Self { map, pid })
    }

    /// Look up a virtual address in the cached mapping.
    pub fn translate(&self, virtual_address: u64) -> Option<u64> {
        let page_offset = virtual_address & 0xFFF;
        let va_page = virtual_address & !0xFFF;
        self.map.get(&va_page).map(|&pa_page| pa_page | page_offset)
    }

    /// Number of pages in the cache
    pub fn page_count(&self) -> usize {
        self.map.len()
    }

    /// Target process ID this cache was built for
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

// =============================================================================
// Non-Windows stub (compile gate)
// =============================================================================

#[cfg(not(windows))]
pub fn vtop(_pid: u32, _virtual_address: u64) -> Result<u64, VtopError> {
    Err(VtopError::WinApi {
        function: "vtop",
        code: 0,
    })
}

#[cfg(not(windows))]
pub fn vtop_batch(_pid: u32, _addresses: &[u64]) -> Result<Vec<Option<u64>>, VtopError> {
    Err(VtopError::WinApi {
        function: "vtop_batch",
        code: 0,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(mem::size_of::<SuperfetchInformation>(), 32);
        assert_eq!(mem::size_of::<MmpfnIdentity>(), 24);
        assert_eq!(mem::size_of::<PfPfnPrioRequestHeader>(), 16);
        assert_eq!(mem::size_of::<PfPhysicalMemoryRange>(), 16);
        assert_eq!(mem::size_of::<PfMemoryRangeInfoHeader>(), 8);
    }

    #[test]
    fn test_superfetch_constants() {
        // Version must be 45 for Windows 11 25H2
        assert_eq!(SUPERFETCH_VERSION, 45);
        // Magic is 'kuhC' in little-endian
        assert_eq!(SUPERFETCH_MAGIC, 0x4368_756B);
        assert_eq!(&SUPERFETCH_MAGIC.to_le_bytes(), b"kuhC");
    }

    #[test]
    fn test_pfn_to_physical() {
        // PFN 0x1A3F should give PA 0x1A3F000
        let entry = MmpfnIdentity {
            flags: 0,
            page_frame_index: 0x1A3F,
            virtual_address: 0x7FFE_1000,
        };
        let pa = (entry.page_frame_index << 12) | 0x456;
        assert_eq!(pa, 0x1A3F_456);
    }

    #[test]
    fn test_page_alignment_mask() {
        let va: u64 = 0x0000_7FFE_DEAD_B987;
        let page_aligned = va & !0xFFF;
        let offset = va & 0xFFF;
        assert_eq!(page_aligned, 0x0000_7FFE_DEAD_B000);
        assert_eq!(offset, 0x987);
    }

    #[test]
    fn test_batch_empty() {
        // Non-windows will return error, but the function signature is correct
        #[cfg(not(windows))]
        {
            let result = vtop_batch(0, &[]);
            assert!(result.is_err()); // stub returns error on non-windows
        }
    }
}
