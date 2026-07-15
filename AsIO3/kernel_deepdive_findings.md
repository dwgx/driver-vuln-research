# AsIO3 Kernel Deep Dive Findings

Date: 2026-07-11
Source: Workflow journal wf_f649abce-70d + referenced analysis files

---

## 1. How g_goodRanges Is Populated

### Answer: Runtime RAM denylist from MmGetPhysicalMemoryRangesEx2

g_goodRanges is NOT populated from firmware/ACPI/PCI scan. The actual sources:

| Hypothesized Source | Actual? | Notes |
|---------------------|---------|-------|
| Hardcoded static array | FALLBACK ONLY | 2 entries (BIOS + PCI MMIO), used when dynamic count = 0 |
| Registry at init time | SECONDARY FALLBACK | `HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory\.Translated` |
| ACPI/WMI tables | NO | IoWMIOpenBlock/IoWMIQueryAllData are NOT imported |
| PCI BAR scan | NO | PCI scan is for caller cert verification, not range building |
| AsusCertService IOCTL | NO | AsusCertService is caller verification, not range source |

**Primary source**: `MmGetPhysicalMemoryRangesEx2` (Windows kernel API, available on Win10 2004+)
- Resolved dynamically via `MmGetSystemRoutineAddress`
- Returns all physical RAM ranges in the system
- The driver stores these as a DENYLIST (blocks RAM, allows MMIO)

### Population Sequence

1. Driver loads (DriverEntry at INIT:0xD000) -- does NOT populate ranges here
2. First `CreateFile("\\.\Asusgio3")` triggers IRP_MJ_CREATE handler (RVA 0x2777)
3. Handler checks if denylist already populated (null-pointer guard)
4. Calls RVA 0x3138 (caller authorization via ASUS cert check)
5. If authorized: calls RVA 0x2D88 which resolves and calls MmGetPhysicalMemoryRangesEx2
6. Counts entries (terminated by {0,0} sentinel)
7. Stores count at RVA 0x95C0, buffer pointer at RVA 0x95C8

### Fallback (when MmGetPhysicalMemoryRangesEx2 unavailable)

Registry path: `\Registry\Machine\HARDWARE\RESOURCEMAP\System Resources\Physical Memory`
Value: `.Translated`
Parser at RVA 0x39B4 extracts CmResourceTypeMemory (type 3) and CmResourceTypeMemoryLarge (type 7) descriptors.

---

## 2. Runtime Modification Feasibility

### Is the table modifiable after initialization?

**NO -- effectively immutable once populated:**

1. Population is guarded by null-pointer check (only runs if pointers are zero)
2. No code path writes to the buffer after initial population
3. No IOCTL handler modifies `g_physRangeCount` or `g_physRangeBuffer`
4. The `.data` section IS writable (PE characteristics `0xC8000040`), but no driver code exploits this

### Complete IOCTL Audit (none modify ranges)

| IOCTL | Function | Modifies Ranges? |
|-------|----------|-----------------|
| 0xA0400F58-F7C | I/O port read/write | No |
| 0xA0400F80 | MSR read | No |
| 0xA0402010 | Physical memory page read | No - validates first |
| 0xA0402014 | Physical memory page read (extended) | No |
| 0xA0402018 | Physical memory page write | No |
| 0xA040244C | Map physical memory section | No - validates first, caches in linked list |
| 0xA0402450 | HalSetBusDataByOffset | No |
| 0xA0406400-640C | PCI config space read | No |
| 0xA040A488 | Allocate contiguous memory | Adds to linked list cache only (chicken-egg: allocates NEW memory, cannot specify address) |
| 0xA040A48C | Remove linked list entry | No range table modification |

The linked list (Layer 1 validation) is the only runtime-modifiable structure, but it only accepts addresses that ALREADY pass validation.

---

## 3. Kernel Patch Research Results (SIVX64 -> AsIO3 .data)

### Strategy

Use SIVX64's unrestricted physical memory R/W to patch AsIO3's .data section:
- Target: Zero the denylist count at RVA 0x95C0 (reverts to static allowlist mode)
- Alternatively: patch static allowlist at RVA 0x9130 to cover all physical memory
- .data patching is PatchGuard-safe (PatchGuard only monitors .text)

### Execution Results: FAILED at CR3 Discovery

```
[19:31:20.188] [INFO] Step 1: SIVX64 driver setup...
[19:31:20.981] [INFO] SIVDRIVER device opened
[19:31:20.981] [INFO] SIVX64 working (APIC read: ffffffff)
[19:31:20.981] [INFO] Step 2: Locating AsIO3.sys in kernel...
[19:31:20.992] [INFO] AsIO3: AsIO3.sys @ 0xFFFFF80612850000
[19:31:20.992] [INFO] Step 3: Discovering System CR3...
[19:31:20.992] [INFO] Strategy 1: KPCR via MSR 0xC0000102 (IA32_KERNEL_GS_BASE)...
[19:31:20.992] [WARN] KERNEL_GS_BASE read failed or invalid: 590753247232
[19:31:20.992] [INFO] ntoskrnl base = 0xFFFFF8067D600000
[19:31:20.992] [INFO] Kernel PML4 index = 496 (0x1F0)
[19:31:20.993] [INFO] Strategy 2: PML4 scan for System CR3...
[19:31:21.005] [INFO] Not found in first 16MB. Scanning 16MB-256MB...
[19:31:21.201] [INFO] Strategy 3: Try ANY valid CR3 for kernel-space reads...
[19:31:21.262] [ERR] All CR3 discovery strategies FAILED
```

### Why CR3 Discovery Failed

- Strategy 1 (KPCR via IA32_KERNEL_GS_BASE MSR 0xC0000102): MSR read returned suspicious value 590753247232 (0x89A4400000), likely invalid or SIVX64 doesn't support MSR reads properly
- Strategy 2 (PML4 scan): Scanned 0-256MB of physical memory looking for valid PML4 tables -- not found
- Strategy 3 (brute-force any valid CR3): Also failed

Without CR3, cannot perform virtual-to-physical address translation, cannot write to AsIO3's .data section at its known virtual address.

### What Was Successfully Discovered

- SIVX64 driver operational (APIC ID register read succeeds from physical memory)
- AsIO3.sys kernel base address: `0xFFFFF80612850000` (via NtQuerySystemInformation)
- ntoskrnl.exe base: `0xFFFFF8067D600000`
- Kernel PML4 index: 496 (0x1F0)

---

## 4. Physical Addresses and Offsets

### AsIO3 .data Section Global Variables

| Variable | RVA | Virtual Address | Purpose |
|----------|-----|-----------------|---------|
| MSR whitelist (static) | 0x9000 | 0x140009000 | 29 allowed MSR indices |
| IO port whitelist (static) | 0x9080 | 0x140009080 | 43 allowed port ranges |
| Static phys range entries | 0x9130 | 0x140009130 | 2 MMIO ranges (fallback allowlist) |
| SHA-256 hash of AsusCertService | 0x9150 | 0x140009150 | Caller verification hash |
| PID whitelist array | 0x93C0 | 0x1400093C0 | 64 QWORDs, runtime-populated PIDs |
| Dynamic phys range COUNT | 0x95C0 | 0x1400095C0 | Non-zero = denylist active |
| Dynamic phys range BUFFER PTR | 0x95C8 | 0x1400095C8 | Pointer to RAM range array |
| Dynamic IO port struct | 0x95D0 | 0x1400095D0 | Extended port/MSR/phys data |
| Dynamic IO port data | 0x95D8 | 0x1400095D8 | Port range extension |
| Dynamic MSR data | 0x95E0 | 0x1400095E0 | MSR extension |
| Dynamic phys data | 0x95E8 | 0x1400095E8 | Phys range extension |
| FastMutex (list lock) | 0x9620 | 0x140009620 | Synchronization |
| Mapping linked list head | 0x9670 | 0x140009670 | Active mapping cache |
| ZwQueryInformationProcess cache | 0x9688 | 0x140009688 | Resolved function pointer |

### Static Allowlist Entries (used when denylist count = 0)

| Entry | Base | Size | End | Description |
|-------|------|------|-----|-------------|
| 0 | 0x000E0000 | 0x00020000 | 0x000FFFFF | Legacy BIOS/Video ROM (128KB) |
| 1 | 0xF8000000 | 0x07FFFFFF | 0xFFFFFFFF | PCI MMIO High (128MB) |

### Denylist Entry Format (16 bytes each)

```
Offset 0x00: DWORD PhysicalAddressLow
Offset 0x04: DWORD PhysicalAddressHigh   (combined = QWORD base)
Offset 0x08: DWORD SizeLow
Offset 0x0C: DWORD SizeHigh              (combined = QWORD size)
```

### Kernel Module Addresses (from test run)

| Module | Virtual Address |
|--------|----------------|
| AsIO3.sys | 0xFFFFF80612850000 |
| ntoskrnl.exe | 0xFFFFF8067D600000 |

### Validation Function

- RVA 0x1514 (VA contextual to loaded base)
- Returns 0 = ALLOW, 1 = DENY
- Three-phase: linked list cache -> static allowlist (if count=0) -> dynamic denylist (if count!=0)

---

## 5. Three-Layer Validation Architecture

```
Request: map physical address X, size N

Layer 1: Active Mapping Cache (Linked List at .data+0x670)
  - Walk doubly-linked list
  - If [X, X+N] fully within any cached region -> ALLOW
  - If overlaps but not contained -> DENY
  - If no match -> continue

Layer 2: Static Hardcoded (ONLY when denylist count at .data+0x5C0 == 0)
  - Check 2 entries at .data+0x130
  - Entry 0: BIOS 0xE0000-0xFFFFF
  - Entry 1: PCI MMIO 0xF8000000-0xFFFFFFFF
  - If contained -> ALLOW, else -> DENY

Layer 3: Dynamic RAM Denylist (WHEN count at .data+0x5C0 != 0)
  - Buffer pointer at .data+0x5C8
  - Contains ALL physical RAM ranges
  - If address IN any range -> DENY (it's RAM)
  - If address NOT in any range -> ALLOW (it's MMIO)
```

---

## 6. Key Conclusions

1. **g_goodRanges is a DENYLIST, not an allowlist** -- it blocks RAM while allowing MMIO access

2. **Source is MmGetPhysicalMemoryRangesEx2** -- NOT WMI, NOT ACPI tables, NOT PCI BAR scan

3. **Populated lazily on first device open** -- not at DriverEntry time

4. **Immutable after population** -- no IOCTL modifies it, no runtime API to change it

5. **SIVX64 cross-driver patch theoretically viable but CR3 discovery failed** -- need better CR3 enumeration (larger physical scan range, or alternative method like reading from KUSER_SHARED_DATA)

6. **Patch target is clear**: Writing 0 to `AsIO3_base + 0x95C0` (4 or 8 bytes) would disable the denylist entirely, reverting to the permissive static allowlist (BIOS + PCI MMIO regions only). For full RAM access, additionally patch the static entries at `+0x9130` to cover 0x00000000-0xFFFFFFFFFF.

7. **Alternative bypass**: The AsusCertService named pipe (`\\.\pipe\asuscert`) is accessible without elevation and may proxy IOCTL operations -- but the pipe protocol needs reverse engineering, and even then, the physical memory range restriction still applies at the driver level.
