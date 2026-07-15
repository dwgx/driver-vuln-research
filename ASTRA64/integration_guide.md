# ASTRA64 Backend — Integration Guide

## Where to Paste

Insert the entire contents of `astra64_backend.rs` into
`D:\Project\toolkit\src\saomola-tui\src\driver_chain.rs` **between** the SIVX64
backend's `Drop` impl (ends at line ~760) and the `// ─── Utility Functions` 
section (starts at line ~762).

Paste it **before** this line:

```rust
// ─── Utility Functions ───────────────────────────────────────────────────────
```

So the file structure becomes:

```
// ─── Backend 3: SIVX64 ──────...
  ... (existing SIVX64 code) ...
impl Drop for SivxBackend { ... }

// ─── Backend 4: ASTRA64 ─────...    ← INSERT HERE
  ... (astra64_backend.rs content) ...
impl Drop for Astra64Backend { ... }

// ─── Utility Functions ───────...
fn to_wide(...) { ... }
```

Note: the code uses `thread::sleep`, `Duration`, `ptr`, `to_wide`, `run_sc`,
`log`, `generate_service_name`, `INVALID_HANDLE`, `GENERIC_READ`,
`GENERIC_WRITE`, `FILE_SHARE_READ`, `FILE_SHARE_WRITE`, `OPEN_EXISTING`,
`FILE_ATTRIBUTE_NORMAL`, `CreateFileW`, `DeviceIoControl`, `CloseHandle`,
`GetLastError`, and `PhysMemReader` — all already defined/imported in
driver_chain.rs. No new imports needed.

---

## Changes to `DriverChain::new()`

The report recommends priority: **ASTRA64 > SIVX64 > ASMMAP64 > AsIO3** because
ASTRA64 is not on LOLDrivers and has no range restrictions. However, since AsIO3
is pre-loaded (zero-cost probe) and ASMMAP64 may already be present, the
practical insertion is between AsIO3 and ASMMAP64:

```
1. AsIO3       — pre-loaded on ASUS boards, zero load cost
2. ASTRA64     — our best brought driver, not on blocklists
3. ASMMAP64    — unrestricted but may be WDAC-blocked  
4. SIVX64      — fallback, known to LOLDrivers
```

### Code change in `DriverChain::new()` (replace lines ~59-100)

```rust
pub fn new() -> Self {
    let mut drivers: Vec<Box<dyn PhysMemReader>> = Vec::new();

    // Priority 1: AsIO3 (pre-loaded on ASUS boards, zero load cost)
    log("[chain] Probing AsIO3...");
    let asio3 = AsIO3Backend::new();
    if asio3.is_available() {
        log("[chain] AsIO3 available");
    } else {
        log("[chain] AsIO3 not available");
    }
    drivers.push(Box::new(asio3));

    // Priority 2: ASTRA64 (not on LOLDrivers/HVCI, usermode mapping, no range limits)
    log("[chain] Probing ASTRA64...");
    let astra = Astra64Backend::new();
    if astra.is_available() {
        log("[chain] ASTRA64 available");
    } else {
        log("[chain] ASTRA64 not available");
    }
    drivers.push(Box::new(astra));

    // Priority 3: ASMMAP64 (unrestricted map, but may be WDAC-blocked)
    log("[chain] Probing ASMMAP64...");
    let asmmap = AsmmapBackend::new();
    if asmmap.is_available() {
        log("[chain] ASMMAP64 available");
    } else {
        log("[chain] ASMMAP64 not available");
    }
    drivers.push(Box::new(asmmap));

    // Priority 4: SIVX64 (known to LOLDrivers, last resort)
    log("[chain] Probing SIVX64...");
    let sivx = SivxBackend::new();
    if sivx.is_available() {
        log("[chain] SIVX64 available");
    } else {
        log("[chain] SIVX64 not available");
    }
    drivers.push(Box::new(sivx));

    // Pick first available
    let active = drivers.iter().position(|d| d.is_available());
    if let Some(idx) = active {
        log(&format!("[chain] Active driver: {}", drivers[idx].name()));
    } else {
        log("[chain] WARNING: No drivers available!");
    }

    DriverChain { drivers, active }
}
```

---

## Changes to `probe_all()`

Add the ASTRA64 entry between AsIO3 and ASMMAP64 (insert after the AsIO3 block,
before the ASMMAP64 block):

```rust
// ASTRA64
let astra = Astra64Backend::new();
let avail = astra.is_available();
let reason = if avail {
    "Driver loaded and device opened".to_string()
} else {
    astra.last_error.clone().unwrap_or("Unknown".into())
};
results.push(("ASTRA64".into(), avail, reason));
```

---

## Update the module doc comment

Change the top-of-file doc comment (lines 1-9) to reflect the new 4-driver chain:

```rust
//! Unified physical memory read interface with driver fallback chain.
//!
//! Probes drivers in priority order:
//!   1. AsIO3    — ASUS motherboard driver, usually pre-loaded
//!   2. ASTRA64  — ASUS AURA LED driver, not on blocklists, usermode mapping
//!   3. ASMMAP64 — ASMedia map driver, unrestricted but may be WDAC-blocked
//!   4. SIVX64   — SIV hardware monitor, needs admin, known to LOLDrivers
//!
//! If a read fails on one driver (e.g. range restriction), the chain falls through
//! to the next available backend.
```

---

## Update the test

The test `test_probe_all_returns_three_entries` needs to expect 4 entries:

```rust
#[test]
fn test_probe_all_returns_four_entries() {
    let results = probe_all();
    assert_eq!(results.len(), 4);
    assert_eq!(results[0].0, "AsIO3");
    assert_eq!(results[1].0, "ASTRA64");
    assert_eq!(results[2].0, "ASMMAP64");
    assert_eq!(results[3].0, "SIVX64");
}
```

---

## Key Behavioral Differences from SIVX64

| Aspect | SIVX64 | ASTRA64 |
|--------|--------|---------|
| Memory access | Kernel copies data to IOCTL output buffer | Maps physical pages into usermode VA, caller does memcpy |
| IOCTL input size | 12 bytes: `[u64 addr][u32 size]` | 24 bytes: `[u32 flags][u32 bus][i64 addr][u32 rsv][u32 len]` |
| IOCTL output | Raw data (size bytes) | 8 bytes: mapped VA pointer |
| Cleanup required | None (kernel frees after copy) | MUST call UNMAP IOCTL or kernel pool exhausts |
| Device path | `\\.\SIVDRIVER` | `\\.\Astra32Device0` |
| Privilege enable | SeLoadDriverPrivilege needed before open | Not needed (no access checks post-admin) |
| Range limit | None | None |
| Detection risk | Listed on LOLDrivers | Not listed anywhere |
| File sharing flags | Exclusive (share=0) | Shared (FILE_SHARE_READ\|WRITE) |
| Bonus capabilities | None | MSR read, Port I/O, PCI config R/W |

---

## Driver File Placement

Ensure `ASTRA64.sys` exists at:
```
D:\Project\toolkit\drivers\Vulnerable-Monitors\ASTRA64.sys
```

This matches `ASTRA_DEFAULT_PATH` in the backend code. The alternative relative
path `drivers\ASTRA64.sys` is checked as fallback.

---

## Why ASTRA64 is preferred for AES key scanning

1. **Map-and-scan**: Map a large physical range (e.g. 16MB), SIMD-scan the
   entire region in usermode, then unmap. Far less IOCTL overhead than SIVX64's
   per-read pattern.
2. **Not blocklisted**: Not on LOLDrivers, not on Microsoft's HVCI blocklist,
   not flagged by Windows Defender. Lower detection risk with EAC.
3. **No range restrictions**: Unlike AsIO3's `g_goodRanges` whitelist.
4. **MSR read (bonus)**: `IOCTL 0x800020EC` with MSR index `0xC0000082`
   (IA32_LSTAR) reveals ntoskrnl base — instant KASLR bypass without needing
   NtQuerySystemInformation.
5. **Tiny footprint**: 21KB driver, no dependencies, works XP-64 through Win11.
