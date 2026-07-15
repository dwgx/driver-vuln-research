# AsIO3/Asusgio3.sys: g_goodRanges Deep Firmware Analysis

## Executive Summary

The `g_goodRanges` restriction in AsIO3 is **NOT a simple allowlist**. It is a **DENYLIST of system RAM ranges** that blocks physical memory access to RAM while allowing MMIO. The denylist is populated at runtime from `MmGetPhysicalMemoryRangesEx2` (primary) or the registry Physical Memory resource map (fallback). It is effectively **read-only after initialization** with **no IOCTL to modify it**.

---

## Answer to the Question

**How is g_goodRanges populated?**

| Source | Answer |
|--------|--------|
| A. Hardcoded static array | YES - 2 entries (BIOS + PCI MMIO), but only used as fallback |
| B. Registry at init time | YES - `Physical Memory\.Translated` as fallback |
| C. ACPI/WMI tables | NO - IoWMIOpenBlock/IoWMIQueryAllData are NOT imported |
| D. PCI BAR scan | PARTIALLY - function 0x3138 verifies caller cert via firmware tables |
| E. AsusCertService IOCTL | NO - AsusCertService is the CALLER verification, not range source |

**Primary source: `MmGetPhysicalMemoryRangesEx2`** (Windows kernel API returning all physical RAM ranges)

---

## Three-Layer Physical Address Validation

The validation function at **RVA 0x1514** implements three checks in order:

### Layer 1: Active Mapping Cache (Linked List)

- **Location**: List head at `.data+0x670` (VA 0x140009670)
- **Semantics**: If the requested address is within an already-mapped region, ALLOW
- **Population**: IOCTL 0xA040244C adds entries when it maps physical memory
- **Purpose**: Performance cache for repeat access to validated regions

### Layer 2: Static Hardcoded Ranges (Allowlist - only when denylist inactive)

- **Location**: `.data+0x130` (VA 0x140009130), 2 entries of 16 bytes each
- **Entry 0**: `base=0x000E0000, size=0x00020000` (Legacy BIOS/Video 0xE0000-0xFFFFF)
- **Entry 1**: `base=0xF8000000, size=0x07FFFFFF` (PCI MMIO High 0xF8000000-0xFFFFFFFF)
- **Active when**: Dynamic denylist count at `.data+0x5C0` equals zero
- **Semantics**: ALLOWLIST - only these ranges are permitted

### Layer 3: Dynamic RAM Denylist (Primary enforcement)

- **Count location**: `.data+0x5C0` (VA 0x1400095C0)
- **Buffer location**: `.data+0x5C8` (VA 0x1400095C8)
- **Active when**: Count is non-zero (normal operation after first open)
- **Semantics**: **DENYLIST** - if address falls within ANY entry, ACCESS DENIED
- **Contains**: All physical RAM ranges in the system
- **Effect**: Only addresses NOT in RAM (i.e., MMIO regions) are accessible

### Validation Return Values

```
Return 0 = ALLOW (address is valid for access)
Return 1 = DENY  (triggers STATUS_ACCESS_DENIED = 0xC0000022)
```

---

## Denylist Population Sequence

### Trigger Point

Population occurs in the **IRP_MJ_CREATE handler** (device open), NOT at DriverEntry time.

```
DriverEntry (INIT:0xD000)
  -> real_init (0x16C4): sets up dispatch, creates device
  -> returns

First CreateFile("\\\\.\\Asusgio3") from usermode:
  -> IRP_MJ_CREATE handler (0x2777 in dispatch)
  -> check: is denylist already populated? if yes, skip
  -> call 0x3138: verify caller authorization (ASUS cert check)
  -> if authorized: call 0x2D88: populate physical memory denylist
```

### Method 1 (Primary): MmGetPhysicalMemoryRangesEx2

```c
// Function at RVA 0x2D88
// Resolves MmGetPhysicalMemoryRangesEx2 via MmGetSystemRoutineAddress
// Available on Windows 10 2004+ (build 19041+)

UNICODE_STRING funcName = L"MmGetPhysicalMemoryRangesEx2";
PVOID func = MmGetSystemRoutineAddress(&funcName);
if (func) {
    PHYSICAL_MEMORY_RANGE* ranges = func(0, 0);  // get all ranges
    // Count entries (terminated by {0,0})
    int count = 0;
    while (ranges[count].BaseAddress || ranges[count].NumberOfBytes) count++;
    
    // Store in globals
    g_physRangeCount = count;              // at 0x1400095C0
    g_physRangeBuffer = AllocAndCopy(ranges, count * 16);  // at 0x1400095C8
}
```

### Method 2 (Fallback): Registry Physical Memory Map

```c
// Falls back when MmGetPhysicalMemoryRangesEx2 is unavailable
// Registry path (string at RVA 0x7A70):
//   \Registry\Machine\HARDWARE\RESOURCEMAP\System Resources\Physical Memory
// Value name (string at RVA 0x7B00):
//   .Translated

// Opens the key, reads CM_RESOURCE_LIST value
// Parser at RVA 0x39B4 extracts CmResourceTypeMemory (type 3) and
// CmResourceTypeMemoryLarge (type 7) descriptors
// Supports large memory descriptors with flags 0x200/0x400/0x800
// (shift sizes 8/16/32 for high addresses)

// Populates same globals: g_physRangeCount and g_physRangeBuffer
```

### Denylist Entry Format

Each entry is 16 bytes:
```
Offset 0x00: DWORD PhysicalAddressLow
Offset 0x04: DWORD PhysicalAddressHigh  (combined = QWORD base)
Offset 0x08: DWORD SizeLow
Offset 0x0C: DWORD SizeHigh             (combined = QWORD size)
```

---

## Mutability Analysis

### Is the table read-only after init?

**YES, effectively immutable:**

1. Population is guarded by null-pointer check (only runs if pointers are zero)
2. No code path writes to the buffer after initial population
3. No IOCTL handler modifies `g_physRangeCount` or `g_physRangeBuffer`
4. `.data` section IS writable (characteristics `0xC8000040`), but no code exploits this

### Is there an IOCTL that adds entries?

**NO.** Complete IOCTL audit:

| IOCTL | Function | Modifies Ranges? |
|-------|----------|-----------------|
| 0xA0400F58-F7C | I/O port read/write (byte/word/dword) | No |
| 0xA0400F80 | MSR read | No |
| 0xA0402010 | Physical memory page read (MmMapIoSpace) | No - validates first |
| 0xA0402014 | Physical memory page read (extended) | No |
| 0xA0402018 | Physical memory page write | No |
| 0xA040244C | Map physical memory section (ZwMapViewOfSection) | No - validates first, then caches in linked list |
| 0xA0402450 | HalSetBusDataByOffset (PCI config write) | No |
| 0xA0406400-640C | PCI config space read (via HalGetBusDataByOffset) | No |
| 0xA0406458 | Extended PCI operation | No |
| 0xA040A440-A448 | Indexed I/O port operations | No |

The linked list (Layer 1) is the only runtime-modifiable validation structure, but it only accepts addresses that ALREADY pass validation (chicken-and-egg: you can only cache what's already allowed).

---

## Caller Verification

The driver restricts which processes can use it:

### Primary Check (RVA 0x3138)
- Resolves `ZwQueryInformationProcess` dynamically
- Reads firmware/SMBIOS tables via `ZwQuerySystemInformation(0x4C)`
- Verifies caller relates to ASUS software
- References path: `C:\Program Files (x86)\ASUS\AsusCertService`
- Compares against stored signature data at `.data+0x150`

### Fallback Check (RVA 0x340C)
- Gets calling process PID
- Compares against a hardcoded PID whitelist at `.data+0x3C0`
- Returns `STATUS_ACCESS_DENIED` if not in list

---

## Static Whitelist Tables (IO Ports + MSRs)

For completeness, the I/O port and MSR validation uses similar two-tier structure:

### I/O Port Whitelist (.data+0x080, 43 entries)
Standard x86 ports: SuperIO (0x2E), PIT (0x40-5F), keyboard (0x60-6F), CMOS (0x70-7F), SMI (0xB2), game port (0x200-220), COM ports (0x2E8, 0x2F8, 0x3E8, 0x3F8), LPT (0x278, 0x378), PCI config (0xCF8-CFC), ACPI (0x1800-1C3F), etc.

### MSR Whitelist (.data+0x000, 29 entries)
Intel/AMD MSRs: CORE_THREAD_COUNT (0x35), PLATFORM_INFO (0xCE), PERF_STATUS (0x198), THERM_STATUS (0x1B1), power/energy MSRs (0x606-651), AMD P-state MSRs (0xC001006x), etc.

### Dynamic Extension
Both port and MSR tables have dynamic extension slots at:
- Port dynamic: struct at `0x1400095D0`, data at `0x1400095D8`
- MSR dynamic: struct at `0x1400095D0`, data at `0x1400095E0`
- Populated from same initialization path as physical ranges

---

## Bypass Implications

### Why the driver is NOT suitable for arbitrary physical memory R/W:

1. **RAM is explicitly blocked** - The entire point of g_goodRanges
2. **No runtime modification** - Cannot add RAM to the allowlist
3. **Caller verification** - Must pass AsusCertService check
4. **Validation before caching** - Linked list only stores already-valid addresses

### Theoretical bypass vectors (all require kernel-level access):

1. **Patch the count to 0** at runtime (`g_physRangeCount` at VA `0x1400095C0`)
   - Would revert to static allowlist mode (only BIOS+PCI MMIO)
   - Requires write to kernel memory (defeats the purpose)

2. **Patch the validation function** (NOP the check at RVA 0x4042)
   - `call 0x140001514` -> NOP would skip validation entirely
   - Requires kernel memory write

3. **Race condition on first open**
   - If you can open the device BEFORE the denylist is populated
   - Unlikely: population happens in the same IRP_MJ_CREATE path

4. **Intercept MmGetPhysicalMemoryRangesEx2**
   - Return empty array -> count=0 -> fallback to static allowlist
   - Requires hooking before driver loads

---

## Key Addresses Summary

| Global Variable | RVA | VA | Purpose |
|----------------|-----|-----|---------|
| MSR whitelist (static) | 0x9000 | 0x140009000 | 29 allowed MSR indices |
| IO port whitelist (static) | 0x9080 | 0x140009080 | 43 allowed port ranges |
| Phys range whitelist (static) | 0x9130 | 0x140009130 | 2 allowed phys ranges |
| Dynamic phys range COUNT | 0x95C0 | 0x1400095C0 | Non-zero = denylist active |
| Dynamic phys range BUFFER | 0x95C8 | 0x1400095C8 | Ptr to RAM range array |
| Dynamic IO port struct | 0x95D0 | 0x1400095D0 | Extended port/MSR/phys data |
| Dynamic IO port data | 0x95D8 | 0x1400095D8 | Port range extension |
| Dynamic MSR data | 0x95E0 | 0x1400095E0 | MSR extension |
| Dynamic phys data | 0x95E8 | 0x1400095E8 | Phys range extension |
| Mapping linked list head | 0x9670 | 0x140009670 | Active mapping cache |
| FastMutex (list lock) | 0x9620 | 0x140009620 | Synchronization |

---

## Conclusion

The g_goodRanges mechanism in AsIO3 is a **runtime-populated RAM denylist** sourced from `MmGetPhysicalMemoryRangesEx2` (or registry fallback). It is:

- **NOT from WMI/ACPI** (IoWMI* not imported, contrary to earlier assumptions)
- **NOT from PCI BARs** (PCI scan is for caller verification, not range building)
- **Populated on first device open**, not at DriverEntry
- **Immutable after population** - no IOCTL to modify
- **Semantically a DENYLIST** - blocks RAM, allows everything else (MMIO)

The driver is architecturally designed to prevent usermode processes from reading arbitrary physical memory (RAM) while still allowing access to memory-mapped I/O regions needed by ASUS hardware monitoring utilities.
