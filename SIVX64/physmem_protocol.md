# SIVX64.sys Physical Memory Protocol Reference

## Overview

SIVX64.sys (SIV Hardware Monitor) exposes physical memory read/write via raw IOCTL codes
sent to `\\.\SIVDRIVER` (device type 0x22). **No authentication or access control** is enforced.

The driver uses MmMapIoSpace (or MmMapIoSpaceEx when available) to create kernel virtual
mappings of physical addresses, performs the copy, then unmaps via MmUnmapIoSpace.

**Device Path:** `\\.\SIVDRIVER`
**IOCTL Format:** Raw integer values (NOT standard CTL_CODE). Pass directly as `dwIoControlCode`.

---

## IOCTL 0x10 — Physical Memory Scatter Read

**Purpose:** Read a contiguous block of physical memory into the output buffer.  
**Handler VA:** 0x22164 (PAGE section, file offset 0xEF64)

### Input Buffer

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 8 | PhysicalAddress | 64-bit physical address to read from |
| 0x08 | 4 | Size | Number of bytes to read (used only when InputBufferLength == 0x30) |
| 0x10 | 4 | Count | Scatter count (entries) — when InputBufferLength == 0x30 |
| 0x14 | 4 | Stride | Stride between reads (when InputBufferLength == 0x30) |
| 0x18 | 4 | Unknown | Additional field (when InputBufferLength == 0x30) |
| 0x1C | 4 | Width | Element width: 1-4 (DWORD max per element) |

**Minimum format (InputBufferLength != 0x30):**

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 8 | PhysicalAddress | 64-bit physical address |

When InputBufferLength != 0x30, OutputBufferLength is the read size.

### Validation

1. **InputBufferLength >= 8** — enforced: `cmp ebx, 8; jb fail`
2. **OutputBufferLength range:** `(OutputBufferLength - 4)` must be <= 0x3FFFC  
   → Minimum: 4 bytes, Maximum: 0x40000 bytes (256 KB)
3. **Size field (when used):** validated against OutputBufferLength

### Memory Mapping Mechanism

1. Calls internal function at VA 0x29A50 (the "MapPhys" wrapper)
2. **Cache type logic:**
   - `r9d = (OutputBufferLength <= 0x200) ? 0 : 1`  
   - When r9d == 0: skips cache lookup, uses fresh MmMapIoSpace with `MmNonCached`
   - When r9d != 0: checks internal cache of existing mappings first
3. **MmMapIoSpace call:**
   - Physical address page-aligned: `phys & ~0xFFF`
   - Size page-aligned up: `(offset + size + 0xFFF) & ~0xFFF`
   - Cache type: **MmNonCached** (value 0) via MmMapIoSpace, or PAGE_READWRITE|PAGE_NOCACHE (0x204) via MmMapIoSpaceEx
4. **Mapping cache:** DeviceExtension maintains an array at +0x648 of previously mapped regions (0x28 bytes each). If the requested range falls within a cached mapping, reuses it (lock-increments refcount at +0x20).
5. Returns kernel VA = mapped_base + (phys & 0xFFF)

### Data Copy

Two modes based on InputBufferLength:

**Simple mode (InputBufLen != 0x30):**
- Copies OutputBufferLength bytes from mapped physical memory to IRP output buffer
- Copy loop: 4 bytes at a time (`mov eax, [rcx]; mov [rdi], eax; add rdi,4; add rcx,4`)

**Scatter mode (InputBufLen == 0x30):**
- Uses Count, Stride, and Width fields
- Three sub-modes based on element width field at [input+0x1C]:
  - Width == 4: reads DWORDs at stride intervals, copies to output buffer as contiguous DWORDs
  - Width < 4: byte-by-byte copy with stride and bit-interleave logic
  - Special: bit-shift/mask operations for sub-byte register fields

### Unmap

After copy completes, calls unmap wrapper at VA 0x29C2C:
- If mapping came from cache: decrements refcount (lock add [entry+0x20], -1)
- If fresh mapping: calls MmUnmapIoSpace directly

### Return Values

| Status | Meaning |
|--------|---------|
| STATUS_SUCCESS (0) | Read completed, IoStatus.Information = bytes read |
| 0xC00000E6 | MmMapIoSpace returned NULL (physical address not mappable) |
| 0xC000000D | STATUS_INVALID_PARAMETER (scatter entry validation failed) |

### Error Handling

- No __try/__except around the copy loop
- Invalid physical addresses that MmMapIoSpace cannot map return 0xC00000E6
- No bugcheck on failure — graceful error return
- Debug logging when DeviceExtension[0] bit 4 is set (detailed trace of addresses/sizes)

---

## IOCTL 0x13 — Physical Memory Bulk Read

**Purpose:** Read a large contiguous block of physical memory (0x400–0xFFFC00 bytes).  
**Handler VA:** 0x21EC4 (PAGE section, file offset 0xECC4)

### Input Buffer (METHOD_BUFFERED — uses SystemBuffer)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | PhysAddrLow | Lower 32 bits of physical address |
| 0x04 | 4 | PhysAddrHigh | Upper 32 bits of physical address |

Total: 8 bytes input.

### Validation

1. **InputBufferLength == 8** exactly: `cmp ebx, 8; jne fail`
2. **OutputBufferLength range:** `(OutputBufferLength - 0x400)` must be <= 0xFFFC00  
   → Minimum: 0x400 bytes (1 KB), Maximum: 0x1000000 bytes (16 MB)
3. Physical address is reconstructed as QWORD from the two DWORD fields

### Process Flow

1. **ProbeForRead** on input buffer (8 bytes, alignment 4)
2. **ProbeForWrite** on output buffer (OutputBufferLength bytes, alignment 8) — uses Irp->UserBuffer (MDL-mapped)
3. **MapPhys** (same VA 0x29A50 wrapper as IOCTL 0x10):
   - `r9d = 0` (always MmNonCached for bulk reads)
   - Maps the full OutputBufferLength at the specified physical address
4. **Memory copy** via internal memcpy function at VA 0x12E10:
   - `rcx = destination (Irp->UserBuffer MDL-mapped)`, `rdx = mapped kernel VA`, `r8d = size`
5. **Unmap** the mapping

### Key Difference from Scatter (0x10)

| Feature | 0x10 (Scatter) | 0x13 (Bulk) |
|---------|----------------|-------------|
| Min size | 4 bytes | 0x400 (1024) bytes |
| Max size | 0x40000 (256 KB) | 0x1000000 (16 MB) |
| Cache mode | NonCached (small) / Cached (>512) | Always NonCached |
| Buffer method | SystemBuffer (buffered I/O) | MDL-mapped UserBuffer (direct I/O) |
| Input format | 8+ bytes, complex scatter | Exactly 8 bytes (phys addr) |
| Copy method | Inline DWORD loop | Optimized memcpy |

### Return Values

| Status | Meaning |
|--------|---------|
| STATUS_SUCCESS (0) | Read completed, IoStatus.Information = OutputBufferLength |
| 0xC00000E6 | MmMapIoSpace failed (unmappable physical address) |

---

## IOCTL 0x14 — Physical Memory Map (Register Scatter R/W)

**Purpose:** Map physical memory and perform scatter read/write on hardware registers.  
**Handler VA:** 0x21B91 (PAGE section, file offset 0xE991)  
**This is the most complex and dangerous IOCTL — supports WRITES.**

### Input Buffer Structure

**Header (0x30 bytes minimum):**

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 8 | PhysicalAddress | Base physical address to map |
| 0x08 | 4 | MapSize | Size of region to map (bytes) |
| 0x0C | 2 | Reserved | Padding |
| 0x0E | 2 | Flags | Operation flags (see below) |
| 0x10 | 4 | Reserved | |
| 0x14 | 2 | EntryCount | Number of scatter entries following |
| 0x16-0x2F | | Padding | Alignment/reserved |

**Scatter entries (0x18 bytes each, starting at offset 0x30):**

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | RegisterOffset | Offset into mapped region |
| 0x04 | 4 | Mask | Bitmask for read-modify-write |
| 0x08 | 4 | Value | Value to write (OR'd with masked read) |
| 0x0C | 4 | ReadResult | Driver writes back the read value here |
| 0x10 | 4 | FinalValue | Driver writes back the final computed value |
| 0x14 | 4 | Reserved | |

### Flags Field (offset 0x0E in header)

| Bit | Meaning |
|-----|---------|
| 0 | Cache type (0=NonCached, 1=Cached — passed as r9 to MapPhys) |
| 1 | **Write-enable** — if set, writes computed value back to physical memory |
| 2 | **Read-back** — if set, reads the register again after write |
| 13 | Alignment check — if set, RegisterOffset must be 4-byte aligned |
| 14 | Reserved (size-related validation) |
| 15 | Mode select — QWORD vs DWORD operations |

### Validation

1. **InputBufferLength == OutputBufferLength:** `cmp r13d, ebx; jne fail`
2. **Minimum buffer size: 0x48 bytes:** `cmp ebx, 0x48; jb fail`
3. **Required buffer size:** `(EntryCount * 3 + 6) * 8` must be <= BufferLength
4. **MapSize range:** minimum 0x100 (256 bytes), maximum 0x400000 (4 MB)
5. **Per-entry validation:**
   - RegisterOffset must be < MapSize
   - Mask/Value consistency checks
   - If bit 13 set: RegisterOffset must be 4-aligned (test dl, 3)

### Operation Logic (per scatter entry)

**Mode 1 (Flags bit 15 clear — DWORD operations):**
```
for each entry:
    validate RegisterOffset < MapSize
    validate element_width <= 4
    read_value = *(DWORD*)(mapped_base + RegisterOffset)
    entry.ReadResult = read_value              // write to entry+0x0C
    computed = (read_value & Mask) | Value     // entry+0x04 & entry+0x08
    entry.FinalValue = computed                // write to entry+0x10
    if (flags & 0x02):                         // write-enable bit
        *(DWORD*)(mapped_base + RegisterOffset) = computed
    if (flags & 0x04):                         // read-back bit
        entry.FinalValue = *(DWORD*)(mapped_base + RegisterOffset)
```

**Mode 2 (Flags bit 15 set — QWORD operations):**
```
Similar but reads/writes 8 bytes at a time via QWORD operations.
Entry format has wider fields for QWORD values.
```

### Return Values

| Status | Meaning |
|--------|---------|
| STATUS_SUCCESS (0) | All entries processed, IoStatus.Information = total bytes in buffer |
| 0xC00000E6 | MmMapIoSpace failed |
| 0xC000000D | STATUS_INVALID_PARAMETER (entry validation failure) |

### Error on Invalid Entry

When a scatter entry fails validation (offset out of range, alignment, etc.):
- Sets status to STATUS_INVALID_PARAMETER (0xC000000D)
- If debug flag set in DeviceExtension, logs detailed error info including:
  - Which entry number failed
  - Total entry count
  - The invalid offset and MapSize values
- Still unmaps the physical memory before returning
- Remaining entries are NOT processed

---

## MapPhys Internal Function (VA 0x29A50)

This is the core function used by all physical memory IOCTLs.

### Parameters
- `rcx` = DeviceExtension pointer
- `rdx` = Physical address (full 64-bit)
- `r8d` = Size to map (bytes)
- `r9d` = Cache hint (0 = NonCached, 1 = try cached/reuse)

### Cache/Reuse Logic

The DeviceExtension maintains a mapping cache at offset +0x648, with entries of 0x28 bytes:

| Entry Offset | Field |
|--------------|-------|
| +0x00 | Physical start address |
| +0x08 | Physical end address |
| +0x10 | Kernel virtual address (mapped base) |
| +0x18 | Kernel VA + size (end of mapping) |
| +0x20 | Reference count (atomic) |
| +0x24 | Additional refcount |

When r9d != 0:
1. Acquires fast mutex at DeviceExtension+0x5A0
2. Scans cache entries from +0x648 to current end ([DevExt+0x1B0])
3. For each entry: if `phys_start <= requested_phys` AND `requested_end <= phys_end`, reuses it
4. On cache hit: increments refcount, returns cached kernel VA + offset
5. On cache miss: falls through to fresh MmMapIoSpace

When r9d == 0:
1. Goes directly to fresh mapping (skips cache entirely)

### MmMapIoSpace Selection

DeviceExtension stores function pointers:
- `[DevExt + 0x140]` = MmMapIoSpaceEx (Win10+, if available)
- `[DevExt + 0x138]` = MmMapIoSpace (fallback)

Priority: MmMapIoSpaceEx first (with flags 0x204 = PAGE_READWRITE|PAGE_NOCACHE), else MmMapIoSpace with MmNonCached.

Both are resolved at init via MmGetSystemRoutineAddress.

### Performance Tracking

The function tracks timing and statistics:
- Calls a timing function at [DevExt+0x110] before and after mapping
- Records min/max/histogram of mapping times at DevExt+0x5E4/0x5E8/0x5F0
- Atomic increment of operation count at DevExt+0x5EC

### Return Value
- Success: kernel virtual address pointing to the mapped physical memory (page-offset adjusted)
- Failure: NULL (0) — caller checks and returns STATUS 0xC00000E6

---

## Summary: Rust FFI Usage

### For simple physical memory reads (recommended: IOCTL 0x10):

```rust
// Input: 8 bytes (physical address as u64)  
// Output: buffer of desired size (4..=0x40000 bytes)
let phys_addr: u64 = 0xFEE00000;
let read_size: u32 = 4096;
let input = phys_addr.to_le_bytes();
let mut output = vec![0u8; read_size as usize];
DeviceIoControl(handle, 0x10, &input, &mut output, ...);
```

### For large reads (IOCTL 0x13):

```rust
// Input: exactly 8 bytes (phys_lo: u32, phys_hi: u32)
// Output: 0x400..=0x1000000 bytes (direct I/O, MDL-mapped)
let phys_addr: u64 = target_addr;
let input = phys_addr.to_le_bytes(); // 8 bytes LE
let mut output = vec![0u8; 0x1000]; // 4KB read
DeviceIoControl(handle, 0x13, &input, &mut output, ...);
```

### For register read/write (IOCTL 0x14):

```rust
#[repr(C, packed)]
struct PhysMapHeader {
    phys_addr: u64,       // +0x00
    map_size: u32,        // +0x08
    _reserved1: u16,      // +0x0C
    flags: u16,           // +0x0E: bit0=cache, bit1=write, bit2=readback
    _reserved2: u32,      // +0x10
    entry_count: u16,     // +0x14
    _pad: [u8; 26],       // +0x16..0x2F
}

#[repr(C, packed)]
struct ScatterEntry {
    offset: u32,          // +0x00: offset into mapped region
    mask: u32,            // +0x04: AND mask
    value: u32,           // +0x08: OR value (for write)
    read_result: u32,     // +0x0C: driver fills with read value
    final_value: u32,     // +0x10: driver fills with final value
    _reserved: u32,       // +0x14
}
// flags = 0x00: read-only (read_result populated)
// flags = 0x02: write (computed = (read & mask) | value, then written)
// flags = 0x06: write + readback (reads again after write)
```
