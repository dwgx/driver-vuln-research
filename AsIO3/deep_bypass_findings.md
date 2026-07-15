# AsIO3 (Asusgio3.sys) Deep Bypass Findings - Consolidated Report

**Date**: 2026-07-11
**System**: Windows 11 25H2, Build 26200
**Driver**: AsIO3.sys (Asusgio3 service, RUNNING, 69,768 bytes)
**Service**: AsusCertService v1.3.2 (PID 3760)

---

## Executive Summary

AsIO3.sys was exhaustively analyzed across 7+ exploit iterations to determine if it can be used for arbitrary physical memory access (specifically VRChat AES key extraction). **The driver CANNOT be used for this purpose.** The `g_goodRanges` mechanism is an immutable denylist/allowlist that restricts physical memory access to MMIO regions only. All RAM is blocked with no bypass IOCTL.

**Final verdict**: Use SIVX64.sys (confirmed working) or ASMMAP64.sys instead.

---

## 1. IOCTLs Discovered (42 Total)

### Physical Memory IOCTLs (ALL range-checked)

| IOCTL | Function | Range Check |
|-------|----------|-------------|
| 0xA040200C | Map physical memory via ZwMapViewOfSection | YES |
| 0xA0402010 | Unmap physical memory section | NO (cleanup) |
| 0xA0400F7C | Read physical page (32-bit struct variant) | YES |
| 0xA0400F80 | Write 1/2/4 bytes to physical address | YES |
| 0xA0400F84 | Read full 4KB page from physical address | YES |
| 0xA040244C | Map contiguous memory (32-bit) | YES |
| 0xA040A480 | Map contiguous memory (64-bit) | YES |
| 0xA0402450 | Free mapping | NO (cleanup) |
| 0xA040A488 | Allocate NEW contiguous DMA memory | NO (allocates, not reads) |
| 0xA040A48C | Free DMA allocation | NO (cleanup) |
| 0xA040A490 | Register VA in slot table | NO (bookkeeping) |

### PCI Configuration IOCTLs (NO range check - exploitable)

| IOCTL | Function | Restriction |
|-------|----------|-------------|
| 0xA0400F58 | PCI config read via CF8/CFC | Port whitelist |
| 0xA0400F5C | PCI config write via CF8/CFC | Port whitelist |
| 0xA0400F70 | Bulk PCI config read | Port whitelist |
| 0xA0402000 | HalGetBusDataByOffset | **NONE** |
| 0xA0402004 | HalSetBusDataByOffset | **NONE** |
| 0xA0402014 | Extended PCI write | Port whitelist |
| 0xA0402018 | Extended PCI read | Port whitelist |

### MSR IOCTLs (whitelist of 29 MSRs)

| IOCTL | Function |
|-------|----------|
| 0xA0400F88 | RDMSR |
| 0xA0400F8C | WRMSR |
| 0xA0406458 | RDMSR extended struct |
| 0xA040A45C | WRMSR + readback verify |

### Port I/O IOCTLs (whitelist of 43 port ranges)

| IOCTL | Function |
|-------|----------|
| 0xA0406400-0xA0406408 | Direct port read (byte/word/dword) |
| 0xA040A440-0xA040A448 | Direct port write (byte/word/dword) |
| 0xA0400F60-0xA0400F78 | Indexed/sequential port ops |

### Bus Data IOCTLs (NO PORT WHITELIST - exploitable)

| IOCTL | Function |
|-------|----------|
| 0xA040A540 | Bus data byte (unrestricted port) |
| 0xA040A544 | Bus data word (unrestricted port) |
| 0xA040A548 | Bus data dword (unrestricted port) |

---

## 2. g_goodRanges Analysis Results

### Architecture: Three-Layer Validation (RVA 0x1514)

**Layer 1 - Active Mapping Cache (Linked List at .data+0x670)**
- Doubly-linked list of previously-mapped regions
- Chicken-and-egg: only caches addresses that ALREADY passed validation
- Initially empty, cannot be pre-populated externally

**Layer 2 - Static Hardcoded Ranges (Allowlist, .data+0x130)**
- Active when dynamic denylist count == 0 (BSS zero-initialized)
- Only 2 entries:
  - `0x000E0000 - 0x000FFFFF` (128KB, legacy BIOS/Video ROM)
  - `0xF8000000 - 0xFFFFFFFF` (128MB, PCI MMIO high)

**Layer 3 - Dynamic RAM Denylist (Primary enforcement, .data+0x5C0)**
- Count at VA `0x1400095C0`, buffer pointer at `0x1400095C8`
- Active when count > 0 (normal operation after first device open)
- Semantics: DENYLIST - matches RAM ranges, blocks them
- Contains ALL physical RAM reported by `MmGetPhysicalMemoryRangesEx2`

### Population Source

| Priority | Source | API |
|----------|--------|-----|
| Primary | Kernel API | `MmGetPhysicalMemoryRangesEx2` (Win10 2004+) |
| Fallback | Registry | `HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory\.Translated` |
| NOT used | WMI | IoWMIOpenBlock/IoWMIQueryAllData NOT imported |
| NOT used | PCI BARs | PCI scan is for caller verification only |

### Population Trigger

- Populated lazily on **first IRP_MJ_CREATE** (device open), NOT at DriverEntry
- Guarded by null-pointer check (only runs once)
- **Immutable after initialization** - no IOCTL modifies the table

### Key Global Variables

| Variable | RVA | VA | Purpose |
|----------|-----|-----|---------|
| Static allowlist | 0x9130 | 0x140009130 | 2 MMIO range entries |
| Dynamic count | 0x95C0 | 0x1400095C0 | Non-zero = denylist active |
| Dynamic buffer ptr | 0x95C8 | 0x1400095C8 | Pointer to RAM range array |
| Mapping cache head | 0x9670 | 0x140009670 | Linked list of mapped regions |
| FastMutex | 0x9620 | 0x140009620 | Synchronization lock |

### Conclusion on g_goodRanges

The mechanism is a **runtime-populated RAM denylist** that blocks ALL system RAM while permitting only MMIO. It is:
- NOT from WMI/ACPI (contrary to initial assumptions)
- NOT from PCI BARs
- Populated on first device open, not at DriverEntry
- **Immutable after population** - no IOCTL to modify
- Semantically a DENYLIST: blocks RAM, allows everything else (MMIO)

---

## 3. PCI BAR Exploitation Analysis

### The Attack Vector

Since `HalGetBusDataByOffset` (0xA0402000) and `HalSetBusDataByOffset` (0xA0402004) have **NO restrictions** on bus/device/function/offset, a PCI BAR remap attack is theoretically possible:

```
1. Use 0xA0402000 to enumerate PCI devices and read current BARs
2. Find a device with MMIO BAR in the 0xF8000000+ range (within g_goodRanges)
3. Use 0xA0402004 to reprogram that BAR to point to target physical RAM address
4. Use 0xA0400F84 to read the "MMIO" region (which now maps to RAM)
5. Restore original BAR when done
```

### Risk Assessment

| Risk | Severity | Notes |
|------|----------|-------|
| System crash (BSOD) | HIGH | If device is actively DMA'ing, BAR change causes corruption |
| Data loss | HIGH | Device may write to wrong physical addresses |
| Device lockup | MEDIUM | Some devices hard-fault on BAR change while active |
| Irreversible | LOW | BAR can be restored; PCI spec allows runtime BAR programming |

### Practical Limitations

- Must find a device that is idle (no active DMA transactions)
- BAR must be in the allowed range (0xF8000000-0xFFFFFFFF)
- Remapped address still page-aligned by driver (& 0xFFFFF000)
- HIGH instability risk makes this unsuitable for production use

### Verdict

PCI BAR remap is **theoretically viable but practically dangerous**. System instability makes it unsuitable for reliable VRChat key extraction.

---

## 4. MMIO Remap Research Results

### Bus Data IOCTLs (0xA040A540-A548) - Port Whitelist Bypass

These IOCTLs call `sub_1400012A0` which performs raw `OUT dx, al/ax/eax` with **NO port whitelist check**. Input structure:

```c
struct BusDataInput {  // 0x24 bytes
    DWORD port_number;   // +0x00: ANY port
    DWORD reg_ebx;       // +0x04
    DWORD reg_ecx;       // +0x08
    DWORD reserved;      // +0x0C
    DWORD reg_esi;       // +0x10
    DWORD reg_edi;       // +0x14
    DWORD reg_ebp;       // +0x18
    DWORD data_value;    // +0x20: value to write
};
```

This enables:
- Access ANY I/O port (CF8/CFC for PCI config, 0xB2 for SMI)
- PCI config manipulation without port whitelist
- SMI triggering (port 0xB2)

**Limitation**: These perform OUTPUT only in the direct-call path. Read-back writes to a memory-mapped location from the struct context, not back to usermode buffer directly.

### Kernel Patch via SIVX64 (Failed)

Attempted to use SIVX64 physical memory R/W to patch AsIO3's `.data` section:
- **Target**: Zero denylist count at RVA 0x95C0 (disables Phase 3 denylist)
- **AsIO3 kernel base found**: `0xFFFFF80612850000`
- **CR3 discovery FAILED**: All strategies (KPCR via MSR, PML4 scan, valid CR3 scan) failed
- **Result**: Cannot translate kernel VA to physical address for patching

---

## 5. Access Control Bypass (Partially Successful)

### Device Access (IRP_MJ_CREATE) - BYPASSED

The driver enforces:
1. **Security Descriptor (DACL)**: Custom DACL restricts device open to ASUS processes
2. **Authenticode certificate check**: Verifies calling process binary signature
3. **SHA-256 file hash check**: Hashes first 0xFF0000 bytes, compares to stored hash at .data+0x150

**Bypass achieved via code injection into AsusCertService**:
```
1. sc start AsusCertService
2. WriteProcessMemory: NOP the WinVerifyTrust JE at RVA 0x135B6
3. Pipe register PID: write to \\.\pipe\asuscert, receive "OK!"
4. VirtualAllocEx: allocate RWX page in service
5. WriteProcessMemory: write shellcode (CreateFileW + DeviceIoControl)
6. CreateRemoteThread: execute in service context
7. Handle obtained successfully
```

### IOCTL PID Check - BYPASSED

Driver checks `IoGetRequestorProcess()` at IOCTL dispatch time. Calls from external processes via DuplicateHandle are rejected (ERROR 24).

**Bypass**: Execute DeviceIoControl from within the service process via injected shellcode.

### g_goodRanges - NOT BYPASSED (CANNOT BE BYPASSED)

Even with full device access and valid IOCTL dispatch, ALL RAM addresses are blocked:
- 0x00001000, 0x00007000, 0x00010000, 0x00080000 - ALL ERROR 24
- 0x000A0000 (VGA), 0x000F0000 (BIOS shadow) - ALL ERROR 24

### Hash Version Mismatch Discovery

```
Stored hash (driver): CFE4CD5249D06B17139A7D30ECAEB2271F4A11C44E1E3B8BBBE555D7ED017A56
Current AsusCertService.exe (558104 bytes): 67E31590ABC2CC6443DA5679C33FE927...
Old v1.3.2 AsusCertService.exe (497560 bytes): CFE4CD5249D06B17... (MATCH!)
```

The driver hash matches the OLD v1.3.2 binary at:
`C:\Program Files (x86)\ASUS\AsusCertService\1.3.2\AsusCertService.exe`

---

## 6. Generated Code

### Working Exploit Chain (device open only, blocked by g_goodRanges)

| File | Purpose |
|------|---------|
| `D:\Project\toolkit\asio3_client.py` | Reusable client library (full injection chain) |
| `D:\Project\toolkit\asio3_inject_test.py` | Proven 3-stage injection test |
| `D:\Project\toolkit\asio3_ioctl_probe.py` | In-process IOCTL code scanner |
| `D:\Project\toolkit\asio3_size_probe.py` | Buffer size brute-force |
| `D:\Project\toolkit\asio3_proxy_read.py` | Full proxy read (blocked by g_goodRanges) |
| `D:\Project\toolkit\asio3_exploit_v6.py` | Best reference (in-memory patch + ASLR) |
| `D:\Project\toolkit\asio3_kernel_patch.py` | SIVX64-based kernel patch (CR3 discovery failed) |

### Analysis Scripts

| File | Purpose |
|------|---------|
| `report\AsIO3\deep_disasm.py` - `deep_disasm4.py` | Iterative disassembly of driver internals |
| `report\AsIO3\elevated_bypass.py/2.py` | Elevated privilege bypass attempts |
| `report\AsIO3\injection_test.py` | Code injection PoC |
| `report\AsIO3\hash_analysis.py` | SHA-256 hash comparison tool |
| `report\AsIO3\pipe_client.py` | Named pipe protocol client |

---

## 7. Final Conclusions

### AsIO3 is NOT viable for VRChat AES key extraction

The triple-layer protection prevents arbitrary RAM access:
1. **Authenticode + hash check** in IRP_MJ_CREATE - BYPASSED via injection
2. **PID check** at IOCTL dispatch - BYPASSED via in-process execution  
3. **g_goodRanges** physical address restriction - **CANNOT BE BYPASSED**

### Theoretical Bypass Vectors (all require kernel access, defeating the purpose)

| Vector | Feasibility | Notes |
|--------|-------------|-------|
| Zero denylist count (RVA 0x95C0) | Requires kernel write | Circular dependency |
| NOP validation function (RVA 0x1514) | PatchGuard unsafe (.text) | Would trigger BSOD |
| PCI BAR remap attack | HIGH crash risk | Theoretically viable |
| Hook MmGetPhysicalMemoryRangesEx2 | Must intercept before driver loads | Timing impossible |
| Race condition on first open | Population in same IRP path | No window |

### Recommended Alternatives

| Driver | Status | Restrictions |
|--------|--------|-------------|
| **SIVX64.sys** | Confirmed working (loaded, device opened) | NONE on physical addresses |
| **ASMMAP64.sys** | Available, untested | NONE (unrestricted MmMapIoSpace) |
| **WER dump method** | Proven for Unity 6 Beta | Requires killing EAC + crash |

### Key Takeaway

AsIO3 is architecturally designed as a hardware monitoring driver. Its physical memory access is intentionally restricted to MMIO regions (sensor chips, PCI device registers). The denylist is populated from the OS's physical memory map and is immutable at runtime. No amount of usermode exploitation can overcome this kernel-enforced restriction without a separate kernel R/W primitive (which would make AsIO3 unnecessary).

**Use SIVX64.sys** - it has no address restrictions and is already integrated in `driver_chain.rs`.
