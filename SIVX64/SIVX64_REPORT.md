# SIVX64.sys — Complete Reverse Engineering Report

**SHA256**: `33903e8fa9f0a2acaa4784d645e309b0bd780693824b6c2c5fef257238c77478`
**MD5**: `81d040540015fe998a4cc4bf9a4e8598`
**Size**: 211,144 bytes
**Functions**: 180 (via .pdata)

## Signing

- Signer: RH Software (SIV - System Information Viewer)
- Authority: Microsoft WHCP
- Valid: 2025-07-17 to 2026-07-15
- NOT on LOLDrivers, HVCI blocklist, or any known CVE

## Access Control (IRP_MJ_CREATE)

The driver's device open handler requires **SeLoadDriverPrivilege** to be enabled in the caller's token.

```
1. Driver creates \BaseNamedObjects\SIV_Driver_Event (kernel sync event)
2. On IRP_MJ_CREATE:
   a. Check caller file path against '\GPIO-EXT' / '\GPIO-INT' (skip privilege for GPIO)
   b. Call SeSinglePrivilegeCheck(SeLoadDriverPrivilege, PreviousMode=1)
   c. If FALSE → return STATUS_ACCESS_DENIED (0xC0000022)
   d. If TRUE → allow open, proceed to dispatch
```

**Bypass**: Call `AdjustTokenPrivileges()` to enable SeLoadDriverPrivilege before `CreateFileW()`.

## IOCTL Interface

| Code | Name | Input | Output | Capability |
|------|------|-------|--------|------------|
| 0x08 | RDMSR | u32 index | u64 value | Read any Model-Specific Register |
| 0x0C | WRMSR | u32 index + u64 val | - | Write MSR (6 whitelisted) |
| 0x10 | PhysMem Scatter | u64 addr + u32 size | bytes | Read 4B-256KB physical memory |
| 0x13 | PhysMem Bulk | u64 addr + u32 size | bytes | Read 1KB-16MB physical memory |
| 0x14 | PhysMem Map | addr+size+flags | VA | Map physical→usermode (R/W) |
| 0x44 | Port I/O | port addr | value | Read hardware I/O port |
| 0x48 | PCI Config | bus/dev/fn/off | u32 | Read PCI configuration space |

## WRMSR Whitelist

Only these MSRs can be written:
- 0x38D (IA32_FIXED_CTR_CTRL)
- 0x38F (IA32_PERF_GLOBAL_CTRL)
- 0x19C (IA32_THERM_STATUS)
- 0x110A, 0x1147 (vendor-specific)
- 0xC0000086 (AMD-specific)

## Physical Memory Read Capabilities

| IOCTL | Min Size | Max Size | Use Case |
|-------|----------|----------|----------|
| 0x10 (Scatter) | 4 bytes | 256 KB | Small targeted reads |
| 0x13 (Bulk) | 1 KB | ~16 MB | Large memory scans |
| 0x14 (Map) | page | unlimited | Persistent mapping |

**No range restrictions** — any physical address is accessible.

## Detection Vectors

| Vector | Status | Mitigation |
|--------|--------|------------|
| PiDDBCacheTable | Permanent trace | Randomize service name |
| MmUnloadedDrivers | Rotates (64 entries) | Unload quickly |
| Hash blocklist | NOT listed | Low risk |
| Device name | `\Device\SIVDRIVER` visible | Brief window |
| Named event | `SIV_Driver_Event` exists | Cleaned on unload |

## Operational Security Notes

1. Load time: ~800ms (create+start+open)
2. Service name: randomized per session
3. Cleanup: automatic on Drop (stop+delete service, close handle)
4. No persistent artifacts after unload except PiDDBCacheTable entry
5. EAC kernel driver (EasyAntiCheat_EOSSys) is STOPPED on this system
6. When VRChat is running, EAC will be ACTIVE — timing matters
