# AsIO3 (Asusgio3.sys) - g_goodRanges Deep Analysis

## Executive Summary

**The previous analysis claiming "g_goodRanges covers all 31.38GB RAM" was WRONG.**

The static g_goodRanges table contains exactly TWO entries, both covering MMIO regions only:
- `0x000E0000 - 0x000FFFFF` (upper BIOS area, 128KB)
- `0xF8000000 - 0xFFFFFFFF` (high MMIO, 128MB)

All physical RAM (0x00000000-0x000DFFFF, 0x00100000-0xF7FFFFFF, and everything above 4GB) is **BLOCKED**. There is **NO bypass** via any IOCTL code path.

---

## IOCTL 0xA040200C Handler - Complete Disassembly

### Dispatch Path
```
IRP_MJ_DEVICE_CONTROL handler at VA 0x140001A00
  -> IOCTL code in ECX from IO_STACK_LOCATION[+0x18]
  -> 0xA040200C comparison at 0x140001F9E
  -> Handler function called at 0x140001FB0: call 0x140004290
  -> Parameters: RCX=IRP, EDX=OutputBufferLength, R8D=InputBufferLength
```

### Handler Function (0x140004290)
```
Parameters:
  RCX = IRP pointer
  EDX = OutputBufferLength (determines 32-bit vs 64-bit mode)
  R8D = InputBufferLength

Flow:
  1. if OutputBufLen < 0x1028 -> STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
  2. rbx = IRP->AssociatedIrp.SystemBuffer
  3. if OutputBufLen == 0x1020:
       phys_addr = [rbx+0x14] & 0xFFFFF000  (32-bit, page-aligned)
       [rbx+0x18] = 0  (clear output field)
     else (>= 0x1028):
       phys_addr = [rbx+0x18] & 0xFFFFFFFFFFFFF000  (64-bit, page-aligned)
       [rbx+0x20] = 0
  4. if OutputBufLen == 0 -> STATUS_INVALID_PARAMETER
  5. size = [rbx+0x10]
  6. Call map_physical(phys_addr, size, &mapped_va, &handle) at 0x140004018
  7. Store results back in SystemBuffer
  8. Return
```

### Input Buffer Structure (METHOD_BUFFERED, shared buffer)
```c
// For OutputBufferLength >= 0x1028 (64-bit mode):
struct ASIO3_PHYS_MAP_INPUT {
    BYTE   unknown[0x10];        // +0x00: unused/reserved
    DWORD  size;                 // +0x10: bytes to map
    DWORD  pad;                  // +0x14: alignment padding
    UINT64 physical_address;     // +0x18: target physical address
    UINT64 mapped_va;            // +0x20: OUTPUT - kernel VA (handle)
    // ... (total buffer >= 0x1028 bytes)
};

// For OutputBufferLength == 0x1020 (32-bit mode):
struct ASIO3_PHYS_MAP_INPUT_32 {
    BYTE   unknown[0x10];        // +0x00
    DWORD  size;                 // +0x10
    DWORD  physical_address;     // +0x14: 32-bit physical address
    UINT64 mapped_va;            // +0x18: OUTPUT
    // ... (total buffer = 0x1020 bytes)
};
```

---

## Range Validation Function (0x140001514)

### Parameters
- RCX = physical_address (start)
- EDX = size (bytes)
- Returns: 0 = ALLOWED, non-zero = DENIED

### Three-Phase Check Algorithm

#### Phase 1: Runtime Linked List
```
Location: [RIP + 0x8150] at VA 0x140009670
Structure: Doubly-linked list with LIST_ENTRY + metadata
Entry format:
  +0x00: Flink (next)
  +0x08: Blink (prev)
  +0x10: DeviceObject/identifier
  +0x18: base_address (QWORD)
  +0x20: size (QWORD)

Logic: Walk list. For each entry:
  - If request fully contained in [base, base+size] -> ALLOW (return 0)
  - If request overlaps but not contained -> DENY (return 1)
  - If no match, continue to next entry

Initially EMPTY (head points to itself as sentinel).
Only populated by IOCTL 0xA040A488 which allocates NEW contiguous memory.
```

#### Phase 2: Static Hardcoded Table (default path)
```
Condition: Used when flag at RVA 0x95C0 == 0 (BSS zero-initialized = default)
Location: RVA 0x9130 in .data section
Format: 2 entries, 16 bytes each {base_lo:4, base_hi:4, size_lo:4, size_hi:4}

Entry 0: base=0x000E0000, size=0x00020000, end=0x00100000
  -> Upper BIOS/ROM area (896KB - 1MB)

Entry 1: base=0xF8000000, size=0x07FFFFFF, end=0xFFFFFFFF
  -> High MMIO (3.875GB - 4GB): PCI BARs, LAPIC, IOAPIC

Loop: r8 from 0 to 0x20, step 0x10 (exactly 2 iterations)
Same containment logic as Phase 1.
```

#### Phase 3: Dynamic Firmware Table (ACPI-populated)
```
Condition: Used when flag at RVA 0x95C0 != 0
Count: flag value = number of entries
Entries pointer: RVA 0x95E8 (dynamically allocated at runtime)
Struct pointer: RVA 0x95D0 (ACPI descriptor structure)

Populated by: Function at 0x1400039B4 which parses ACPI resource descriptors
  - Type 3 (memory descriptor) and Type 7 (extended address space descriptor)
  - Entries describe system memory regions from firmware

Same 16-byte format and containment logic.
```

#### Final: If No Phase Allows -> DENIED
```
Returns 1 at address 0x14000164C
Caller returns STATUS_ACCESS_DENIED (0xC0000022)
```

---

## Complete IOCTL Map

### Physical Memory IOCTLs (ALL have range check)

| IOCTL | Function | Description | Handler VA |
|-------|----------|-------------|-----------|
| 0xA040200C | Map | Map physical address, return handle+VA | 0x140004290 |
| 0xA0402010 | Unmap | Release mapped section | 0x140004160 |
| 0xA0400F7C | Read | Map+read+unmap single value (1/2/4 byte) | 0x140004360 |
| 0xA0400F80 | Write | Map+write+unmap single value | 0x140004490 |
| 0xA0400F84 | R/W | Alternate memory R/W path | 0x140004194 |
| 0xA040244C | Section | ZwOpenSection-based map (also range checked) | 0x14000345C/372C |

### I/O Port IOCTLs (have port whitelist check at 0x14000143C)

| IOCTL | Description |
|-------|-------------|
| 0xA0400F58 - 0xA0400F78 | Various I/O port read/write modes |
| 0xA0402000, 0xA0402004 | PCI config space via 0xCF8/0xCFC |
| 0xA0406400 - 0xA040640C | Direct I/O port byte/word/dword |
| 0xA040A440 - 0xA040A448 | PCI/MMIO via I/O ports |

### MSR Access (no memory range check needed)

| IOCTL | Description |
|-------|-------------|
| 0xA0406458 | RDMSR (reads model-specific register) |

### Memory Whitelist Management

| IOCTL | Description |
|-------|-------------|
| 0xA040A488 | Allocate contiguous memory + add to whitelist |
| 0xA040A48C | Remove entry from whitelist |

### Other

| IOCTL | Description |
|-------|-------------|
| 0xA0400F80 - 0xA0400F94 | Additional I/O and interrupt operations |
| 0xA0402014 | MMIO read via mapped address (0x23-byte struct) |
| 0xA0402018 | MMIO write via mapped address |
| 0xA0402450 | Section object mapping |
| 0xA040A490 | MSR write |
| 0xA040A540 - 0xA040A548 | Advanced PCI/MMIO (uses section mapping) |

---

## Bypass Analysis

### Attempted Bypass Paths - ALL BLOCKED

#### 1. Direct Physical Memory Read (0xA040200C / 0xA0400F7C)
All paths through `map_physical()` at 0x140004018 call the range check at 0x140001514.
There is no conditional skip, no alternate code path, no flag to disable it.

#### 2. IOCTL 0xA040A488 (Add to Whitelist)
This allocates NEW contiguous physical memory via `MmAllocateContiguousMemory()`.
You CANNOT specify which physical address to whitelist - it returns the address
of newly allocated memory. Useless for reading existing process memory.

#### 3. Type/Size Field Manipulation
The "type" field (byte at input+0x00) only selects read width (1/2/4 bytes).
The size field is validated but does not affect the range check logic.
No combination of input values bypasses the check.

#### 4. 32-bit vs 64-bit Mode
Both modes (OutputBufLen == 0x1020 and >= 0x1028) go through identical
range check logic. The only difference is address width.

#### 5. MmMapIoSpace Without Range Check
Only called during driver initialization (ACPI/SMBIOS table reading at 0x140003D80).
Not accessible via any user-mode IOCTL.

#### 6. ZwMapViewOfSection Paths
All paths that call ZwMapViewOfSection (at 0x14000369C, 0x1400036C9, 0x1400038A2,
0x1400038EE) are preceded by a call to 0x140001514 (range check) at 0x140003623
or 0x14000375B.

#### 7. I/O Port Indirect Access
I/O ports are whitelist-checked (43 entries at RVA 0x9080). The allowed ports
include PCI config space (0xCF8/0xCFC) but NOT DMA controller or other ports
that could enable indirect memory access without range checks.

---

## Why the Previous Analysis Was Wrong

The previous claim that "g_goodRanges covers all 31.38GB RAM" was incorrect because:

1. **Confused ACPI resources with whitelist**: The firmware table (Phase 3) does describe
   all system memory regions, but it's populated from ACPI which reports both RAM AND MMIO.
   The ACPI descriptor types 3 and 7 include memory-type resources, but the driver only
   populates this table at initialization and the actual physical addresses in it are
   firmware MMIO regions, not usable RAM.

2. **Static table is the fallback**: Since the dynamic count flag (RVA 0x95C0) starts at 0
   (BSS), the STATIC table with only 2 MMIO entries is used UNLESS the driver successfully
   parses ACPI descriptors during init.

3. **Even if Phase 3 is populated**: The ACPI resource descriptors describe the physical
   memory MAP of the system (what firmware has configured), which includes MMIO BARs,
   not arbitrary RAM access. The entries describe what the hardware monitoring tool
   (ASUS AURA/AI Suite) is expected to access.

---

## Input Structure for Testing

To test IOCTL 0xA040200C properly:
```python
# Python struct for DeviceIoControl
import struct, ctypes

# 64-bit mode (OutputBufLen = 0x1028, InputBufLen = 0x1028)
buf = bytearray(0x1028)
# +0x10: size to map (must be > 0)
struct.pack_into('<I', buf, 0x10, 0x1000)  # map 4KB
# +0x18: physical address (64-bit, will be page-aligned by driver)
struct.pack_into('<Q', buf, 0x18, 0x00001000)  # try to read physical 0x1000

# Call DeviceIoControl with:
#   IOCTL = 0xA040200C
#   InputBuffer = buf
#   InputBufferLength = 0x1028
#   OutputBuffer = buf (same buffer, METHOD_BUFFERED)
#   OutputBufferLength = 0x1028
# Result: STATUS_ACCESS_DENIED (0xC0000022) because 0x1000 is RAM, not in whitelist
```

---

## Verdict

**AsIO3/Asusgio3.sys is NOT usable for reading VRChat process physical memory.**

The g_goodRanges mechanism enforces a strict whitelist that only allows access to:
- BIOS ROM area (0xE0000 - 0xFFFFF)
- High MMIO region (0xF8000000 - 0xFFFFFFFF)

There is no IOCTL, no input combination, no type field, and no sequence of operations
that can bypass this restriction to read arbitrary physical RAM. The driver is designed
exclusively for hardware monitoring (reading sensor chips via MMIO/ports) and has no
exploitable path for general physical memory access.
