# End-to-End AES Key Extraction Pipeline

> Technical design: driver load → Superfetch VtoP → physical scan → key identification
> Primary driver: LnvMSRIO (EAC-safe, WHCP-signed, zero access control)

---

## Pipeline Overview

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐    ┌──────────────┐
│ 1. Load     │ → │ 2. Locate    │ → │ 3. Superfetch   │ → │ 4. Physical  │
│    Driver   │    │    Process   │    │    VtoP Batch   │    │    Scan      │
└─────────────┘    └──────────────┘    └─────────────────┘    └──────────────┘
    ~0.5s              ~0.3s                ~1.0s                 ~2.0s

Total: <4s, ~100-160 IOCTL calls (may require 2 load cycles)
```

---

## Phase 1: Driver Load (0.5s)

### Procedure

```rust
// Randomize service name to defeat PiDDBCacheTable
let svc_name = format!("Lnv{:08X}", rand::random::<u32>());

// Create and start service
sc_create(&svc_name, driver_path)?;  // sc create <name> type=kernel binPath=...
sc_start(&svc_name)?;                // sc start <name>

// Open device handle
let driver = LnvMsrioDriver::open()?;  // CreateFile("\\.\WinMsrDev")
driver.probe()?;                        // Version IOCTL 0x9C402000
```

### Timing Constraint

- Load window must be <2s (EAC NtQuerySystemInformation scan interval)
- Service name randomized per session (defeats PiDDB cache name matching)
- Device object exists only while service is running

---

## Phase 2: Locate Target EPROCESS (0.3s, 50+ IOCTL calls)

### Method: KPCR Chain (Safe, Kernel-Only)

```rust
// Step 1: Read IA32_GS_BASE MSR to get KPCR address
let kpcr = driver.read_msr(0xC0000101)?;  // 1 IOCTL

// Step 2: KPCR → KPRCB → CurrentThread → Process
let kprcb = driver.read_physical_u64(kpcr + 0x180)?;        // KPCR.CurrentPrcb
let current_thread = driver.read_physical_u64(kprcb + 0x8)?; // KPRCB.CurrentThread
let system_process = driver.read_physical_u64(current_thread + 0x220)?; // KTHREAD.Process
// NOTE: KTHREAD+0x220 needs live verification on Build 26200 (not yet confirmed)

// Step 3: Walk ActiveProcessLinks to find target PID
// EPROCESS offsets (Win11 25H2 Build 26200, VERIFIED via exploit_test_results.txt):
//   +0x028 = DirectoryTableBase (CR3)
//   +0x1D0 = UniqueProcessId
//   +0x540 = ActiveProcessLinks (LIST_ENTRY Flink/Blink)
//   +0x338 = ImageFileName
//   +0x87A = Protection (PPL byte)
let target_pid: u32 = get_vrchat_pid();  // From usermode EnumProcesses

let mut eprocess = system_process;
loop {
    let pid = driver.read_physical_u32(eprocess + 0x1D0)?;
    if pid == target_pid {
        break; // Found target EPROCESS
    }
    let flink = driver.read_physical_u64(eprocess + 0x540)?;
    eprocess = flink - 0x540; // ActiveProcessLinks.Flink points to next link, not EPROCESS base
    if eprocess == system_process {
        return Err("target process not found");
    }
}
// 50+ IOCTL calls typical: 1 MSR + 2 KPCR/KPRCB reads + 2 reads per process in list
```

### Why This Works Under EAC

- All reads target kernel-space physical addresses (safe range, no BSoD risk)
- EPROCESS linked list is always resident (non-paged pool)
- No page table walk of user-mode addresses involved
- Total: 50+ physical reads typical (2 per process in list, ~25-50 processes on a live system)

---

## Phase 3: Superfetch VtoP — Resolve Target Heap Pages (1.0s, ~10 IOCTL calls)

### Method

```rust
// Get target process CR3 (DirectoryTableBase)
let cr3 = driver.read_physical_u64(eprocess + 0x028)?; // 1 IOCTL

// Query Superfetch for all physical pages belonging to target process
// This uses NtQuerySystemInformation(SystemSuperfetchInformation) — NO driver IOCTL needed
let target_pages = superfetch_vtop::get_process_physical_pages(target_pid)?;

// Filter to heap/private pages (where AES keys likely reside)
// Superfetch MmpfnIdentity.Flags bits[6:4] = page location
// Active private pages (location = 0, shared = 0) are our targets
let candidate_pages: Vec<u64> = target_pages.iter()
    .filter(|entry| {
        let location = (entry.flags >> 4) & 0x7;
        let shared = (entry.flags >> 11) & 1;
        location == 0 && shared == 0  // Active, private
    })
    .map(|entry| entry.page_frame_index << 12) // PFN to physical address
    .collect();
```

### Page Count Estimate

- VRChat typical working set: 800MB-2GB
- At 4KB/page: 200,000 - 500,000 pages
- Superfetch query returns all in one NtQuerySystemInformation call (no driver IOCTL)
- Filtering to private heap pages: ~50,000-100,000 pages

### No IOCTL Cost

Superfetch uses NtQuerySystemInformation (syscall), NOT driver IOCTLs. This phase costs 0-1 driver IOCTL (just the CR3 read if needed for validation).

---

## Phase 4: Physical Memory Scan — AES Key Identification (2.0s, ~40-60 IOCTL calls)

### AES-128 Key Identification Strategy

AES keys in memory have specific characteristics:

```rust
/// AES-128 key schedule: 176 bytes (11 round keys × 16 bytes)
/// The expanded schedule is almost always adjacent to or near the original 16-byte key.
///
/// Detection heuristics:
/// 1. Entropy: A valid AES key has high entropy (>3.5 bits/byte for 16 bytes)
/// 2. Key schedule validation: If we find 176 bytes where applying AES key expansion
///    to the first 16 bytes reproduces the remaining 160 bytes, it's a confirmed key.
/// 3. Structure proximity: Unity/IL2CPP typically stores crypto state in managed heap
///    objects with a predictable header layout.

fn is_aes128_key_schedule(data: &[u8; 176]) -> bool {
    // Extract the first 16 bytes as the candidate key
    let key = &data[0..16];
    
    // Expand the key and compare with remaining bytes
    let expanded = aes_key_expand_128(key);
    &expanded[16..176] == &data[16..176]
}

fn aes_key_expand_128(key: &[u8]) -> [u8; 176] {
    let mut w = [0u8; 176];
    w[..16].copy_from_slice(key);
    
    let rcon: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
    
    for i in 4..44 {
        let mut temp = [w[i*4-4], w[i*4-3], w[i*4-2], w[i*4-1]];
        if i % 4 == 0 {
            temp.rotate_left(1);
            for b in &mut temp { *b = SBOX[*b as usize]; }
            temp[0] ^= rcon[i/4 - 1];
        }
        for j in 0..4 {
            w[i*4+j] = w[(i-4)*4+j] ^ temp[j];
        }
    }
    w
}
```

### Scanning Strategy: Tiered Batched Reads

```rust
// Strategy: Read pages in batches of 4KB, scan each for AES key schedule pattern.
// Use large reads (4096 bytes = 1 page per IOCTL) to maximize data per IOCTL call.

const PAGE_SIZE: usize = 4096;
const MAX_IOCTL_BUDGET: usize = 60; // Reserve 20 for setup + teardown from 100 total

// Priority ordering for candidate pages:
// 1. Recently modified pages (Superfetch flags)
// 2. Pages in typical Unity heap address ranges
// 3. Remaining private pages (random sample if too many)

let mut pages_to_scan = prioritize_pages(&candidate_pages);
if pages_to_scan.len() > MAX_IOCTL_BUDGET {
    pages_to_scan.truncate(MAX_IOCTL_BUDGET);
}

let mut found_keys: Vec<[u8; 16]> = Vec::new();

for phys_addr in &pages_to_scan {
    if !is_safe_phys_addr(*phys_addr) {
        continue;
    }
    
    // Read one full page (1 IOCTL call)
    let page_data = driver.read_physical_memory(*phys_addr, PAGE_SIZE)?;
    
    // Scan for AES key schedules within the page
    for offset in (0..PAGE_SIZE - 176).step_by(16) {
        let candidate: [u8; 176] = page_data[offset..offset+176].try_into().unwrap();
        if is_aes128_key_schedule(&candidate) {
            let key: [u8; 16] = candidate[0..16].try_into().unwrap();
            found_keys.push(key);
        }
    }
}
```

### IOCTL Budget Breakdown

| Phase | IOCTL Calls | Notes |
|-------|-------------|-------|
| Driver probe | 1 | Version check |
| MSR read (GS_BASE) | 1 | KPCR location |
| EPROCESS walk | 50-100 | 2 reads per process (PID + Flink), ~25-50 processes |
| CR3 read | 1 | DirectoryTableBase |
| Page scans | 40-60 | One 4KB page per IOCTL |
| **Total** | **93-163** | May exceed 100 budget — see multi-load strategy |

### What If 60 Pages Isn't Enough?

If no key is found in the first 60 pages:
1. Unload driver (close handle, sc stop, sc delete)
2. Wait 30s (rotate MmUnloadedDrivers ring buffer)
3. Reload with new service name
4. Scan next 60 pages

This gives effectively unlimited scanning with <100 IOCTLs per load cycle.

---

## Phase 5: Cleanup (0.2s)

```rust
// Close device handle (removes from handle table — EAC handle scan)
drop(driver);

// Stop and delete service
sc_stop(&svc_name)?;
sc_delete(&svc_name)?;

// The driver binary remains on disk — consider deleting or leaving for future use
```

---

## Alternative Path: Direct Physical Scan Without Superfetch

If Superfetch returns no results (disabled, or SeProfileSingleProcessPrivilege denied):

```rust
// Fallback: Scan all physical RAM for AES key schedules
// Total RAM: ~32GB = 8,388,608 pages
// At 60 pages/load: 139,810 load cycles = IMPRACTICAL
//
// Better fallback: Use CR3 + kernel page table walk for KERNEL addresses only
// (kernel addresses don't BSoD — only user-mode PTEs cause crashes)
//
// Walk kernel PTE entries to find pool allocations, then scan those.
// Kernel pool = NonPagedPool — always in safe physical range.
```

This fallback is complex and high-risk. Superfetch is the correct path.

---

## EAC Evasion During Operation

| Time Window | Action | EAC Risk |
|-------------|--------|----------|
| T+0.0s | Load driver (random name) | LOW — PiDDB entry created but EAC scans at intervals |
| T+0.5s | Open handle | LOW — handle exists briefly |
| T+0.8s | Read KPCR/EPROCESS | ZERO — pure physical reads, no syscall hooks |
| T+1.8s | Superfetch query | ZERO — standard usermode API, not hooked |
| T+2.0s | Physical page scans | ZERO — pure physical reads |
| T+3.5s | Close handle + unload | MmUnloadedDrivers entry created |
| T+4.0s | sc delete | Service registry key removed |

Key principles:
- Total driver load time: <4s (well within EAC scan interval)
- No suspicious API calls (no NtReadVirtualMemory of protected process)
- No open handles persist (closed before next EAC sweep)
- Service name randomized (defeats name-based detection)
- Driver file SHA-256 not on any known blocklist (as of 2026-07-15)

---

## Data Flow Diagram

```
User Mode                          Kernel Mode                    Physical Memory
─────────────────────────────────────────────────────────────────────────────────
                                                                   
EnumProcesses()                                                    
  → VRChat PID                                                     
                                                                   
CreateFile("\\.\WinMsrDev")                                       
  → device handle                  LnvMSRIO IRP_MJ_CREATE        
                                                                   
DeviceIoControl(RDMSR)                                            
  → KPCR phys addr                 _rdmsr(0xC0000101)             
                                                                   
DeviceIoControl(READ)                                              
  ─── × 50-100 ──→                  MmMapIoSpace → copy            ← EPROCESS chain
  → target EPROCESS addr                                           
                                                                   
NtQuerySystemInformation(79)                                       
  → PFN list for target PID       Superfetch subsystem            ← PFN database
  → physical addresses                                             
                                                                   
DeviceIoControl(READ)                                              
  ─── × 40-60 ──→                  MmMapIoSpace → copy            ← target heap pages
  → raw page data                                                  
                                                                   
aes_key_expand_128() validation                                    
  → confirmed AES-128 key                                          
                                                                   
CloseHandle + sc stop + sc delete                                  
```

---

## Error Handling

| Error | Recovery |
|-------|----------|
| Driver load fails (VDB blocked) | Fall back to SIVX64 or IOMap64 |
| Device open fails (Access denied) | Verify admin, check HVCI status |
| KPCR read returns 0 | Retry on different CPU core (affinity mask) |
| EPROCESS walk loops | Break after 1000 iterations (process not found) |
| Superfetch returns empty | Enable SeProfileSingleProcessPrivilege, retry |
| Physical read BSoDs | Address outside safe range — BUG in validation |
| No AES key found in budget | Reload driver, scan next page batch |
| EAC ban detected | Stop immediately, rotate driver to fallback |

---

## Build 26200 Kernel Offsets

```
KPCR + 0x180          = CurrentPrcb (KPRCB pointer)
KPRCB + 0x008         = CurrentThread (KTHREAD pointer)
KTHREAD + 0x220       = Process (EPROCESS pointer)          [NEEDS LIVE VERIFICATION]
EPROCESS + 0x028      = DirectoryTableBase (CR3)            [VERIFIED]
EPROCESS + 0x1D0      = UniqueProcessId                     [VERIFIED]
EPROCESS + 0x540      = ActiveProcessLinks (LIST_ENTRY)     [VERIFIED]
EPROCESS + 0x248      = Token                               [UNVERIFIED — offset from symbols, not tested]
EPROCESS + 0x338      = ImageFileName (15-char)             [VERIFIED]
EPROCESS + 0x87A      = Protection (PPL byte)               [VERIFIED]
```
