# BS_RCIO64.sys Static Reverse Engineering Report

## Summary

| Field | Value |
|-------|-------|
| Driver | BS_RCIO64.sys |
| Vendor | BIOSTAR Group |
| CVE | CVE-2021-44852 |
| SHA-256 | `d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e` |
| File Size | 24,592 bytes |
| Build Date | 2019-01-11 02:19:46 UTC |
| Version | 10.0.1901.1100 |
| PDB Path | `e:\code\driver_workspace\racing\2019_01_11_for_win10\driver\objfre_wnet_amd64\amd64\BS_RCIO64.pdb` |

---

## 1. PE Metadata

- **Machine**: AMD64 (x86-64)
- **Image Base**: 0x10000
- **Entry Point RVA**: 0x715C (in INIT section)
- **Subsystem**: NATIVE (kernel driver)
- **Total Imports**: 27 functions (25 from ntoskrnl.exe, 2 from HAL.dll)

### Sections

| Name | VirtAddr | VirtSize | RawSize | Purpose |
|------|----------|----------|---------|---------|
| .text | 0x1000 | 0x23A8 | 0x2400 | Code (handlers, phys mem R/W) |
| .rdata | 0x4000 | 0x02B0 | 0x0400 | IAT, read-only data |
| .data | 0x5000 | 0x014C | 0x0200 | Global state (semaphore, etc) |
| .pdata | 0x6000 | 0x0168 | 0x0200 | Exception unwind data |
| INIT | 0x7000 | 0x0550 | 0x0600 | DriverEntry (discardable) |
| .rsrc | 0x8000 | 0x0410 | 0x0600 | Version info resource |

### Key Imports

| API | Purpose in Driver |
|-----|-------------------|
| `MmMapIoSpace` | Map physical memory to kernel virtual address |
| `MmUnmapIoSpace` | Unmap after access |
| `IoCreateDevice` | Create device object (no security!) |
| `IoCreateSymbolicLink` | Create \DosDevices\BS_RCIO symlink |
| `IoStartPacket` / `IoStartNextPacket` | Queued IRP processing |
| `KeWaitForSingleObject` / `KeReleaseSemaphore` | Serialize physical memory access |
| `HalGetBusDataByOffset` / `HalSetBusDataByOffset` | PCI configuration space access |
| `PsCreateSystemThread` | Create kernel threads from IOCTL |

---

## 2. Device & Strings

### Device Configuration

```
Device Name:  \Device\BS_RCIO
Symbolic Link: \DosDevices\BS_RCIO
User-Mode Path: \\.\BS_RCIO
Device Type:  FILE_DEVICE_UNKNOWN (0x22)
Exclusive:    FALSE (multiple handles allowed)
Flags:        DO_BUFFERED_IO
Extension:    48 bytes
```

### Strings of Interest

- `\Device\BS_RCIO` - kernel device name
- `\DosDevices\BS_RCIO` - user-accessible symlink
- `BIOSTAR Group` - vendor
- `I/O Interface driver file` - self-description
- PDB path reveals source: `e:\code\driver_workspace\racing\2019_01_11_for_win10\`

---

## 3. Access Control Analysis (CRITICAL)

### IRP_MJ_CREATE Handler (RVA 0x2BE4)

The CREATE handler is trivial - 13 instructions total:

```asm
sub  rsp, 0x28
mov  rax, [rcx + 0x40]       ; DeviceObject->DeviceExtension
xor  ecx, ecx
mov  r8, rdx                  ; IRP
mov  [rax + 0x18], rcx        ; Clear extension fields
mov  [rax + 0x28], rcx
mov  byte ptr [rax + 0x21], cl
mov  dword ptr [rdx + 0x30], ecx  ; IoStatus.Status = 0
mov  [rdx + 0x38], rcx           ; IoStatus.Information = 0
xor  edx, edx
mov  rcx, r8
call [IofCompleteRequest]     ; Complete with STATUS_SUCCESS
xor  eax, eax                 ; return STATUS_SUCCESS
add  rsp, 0x28
ret
```

**Findings:**
- **NO** token/SID check
- **NO** integrity level verification
- **NO** PID/process name validation
- **NO** custom security descriptor
- Unconditionally returns `STATUS_SUCCESS` (0x00000000)

### IoCreateDevice Call (DriverEntry)

```
IoCreateDevice(
    DriverObject,              // rcx
    DeviceExtensionSize = 48,  // edx = 0x30
    DeviceName = L"\Device\BS_RCIO", // r8
    DeviceType = 0x22,         // r9 (FILE_DEVICE_UNKNOWN)
    Characteristics = 0,       // [rsp+0x20]
    Exclusive = FALSE,         // [rsp+0x28]
    &DeviceObject              // [rsp+0x30]
);
```

**The driver does NOT:**
- Call `IoCreateDeviceSecure()` (which accepts SDDL string)
- Call `ObSetSecurityObjectByPointer()` after device creation
- Set any custom DACL via `ZwSetSecurityObject`
- Check any security context in IRP_MJ_CREATE

### Verdict

The driver itself enforces **ZERO** access control. The default Windows DACL for
`IoCreateDevice` with `FILE_DEVICE_UNKNOWN` typically grants access to SYSTEM and
Administrators only. However:

1. The CVE-2021-44852 report (NephoSec) claims low-integrity access is possible
2. This may depend on the Biostar software installer modifying the service DACL
3. Once a handle is obtained, **any** IOCTL is accepted without further checks

**For toolkit**: Requires admin privileges to open the device handle (standard Windows
default DACL behavior), which is acceptable since driver loading already requires admin.

---

## 4. IOCTL Interface

### IOCTL 0x226040 - Physical Memory READ

```
CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_READ_ACCESS)
```

**Input Buffer (SystemBuffer):**
```c
struct PHYS_READ_INPUT {
    DWORD PhysicalAddress;    // offset 0x00, 32-bit physical address
};
// InputBufferLength >= 4
```

**Output Buffer (SystemBuffer, overwrites input):**
```c
struct PHYS_READ_OUTPUT {
    BYTE Data[OutputBufferLength];  // raw physical memory contents
};
```

**Internal Flow:**
1. `KeWaitForSingleObject(semaphore)` - serialize access
2. Zero-extend 32-bit address to `PHYSICAL_ADDRESS` (64-bit)
3. `VA = MmMapIoSpace(PhysAddr, OutputBufferLength, MmNonCached)`
4. Copy mapped memory to output buffer:
   - Size == 4: single DWORD copy
   - Size == 2: single WORD copy
   - Otherwise: `rep movsb` (byte-by-byte)
5. `MmUnmapIoSpace(VA, size)`
6. `KeReleaseSemaphore(semaphore, 1, 0, FALSE)`

### IOCTL 0x226044 - Physical Memory WRITE

```
CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_READ_ACCESS)
```

**Input Buffer (SystemBuffer):**
```c
struct PHYS_WRITE_INPUT {
    DWORD PhysicalAddress;           // offset 0x00
    BYTE  Data[InputBufferLength-4]; // offset 0x04, data to write
};
// InputBufferLength >= 5 (4 bytes addr + at least 1 byte data)
```

**Output Buffer:** None

**Internal Flow:**
1. `KeWaitForSingleObject(semaphore)` - serialize access
2. `size = InputBufferLength - 4`
3. `VA = MmMapIoSpace(PhysAddr, size, MmNonCached)`
4. Copy input data to mapped memory:
   - Size == 4: single DWORD write
   - Size == 2: single WORD write
   - Size == 1: single BYTE write
   - Otherwise: `memcpy(VA, &Data, size)`
5. `MmUnmapIoSpace(VA, size)`
6. `KeReleaseSemaphore(semaphore, 1, 0, FALSE)`

### All Supported IOCTLs (21 total)

| Code | Function | Purpose |
|------|----------|---------|
| 0x226000 | 0x800 | Callback invocation (dangerous - calls user-supplied function pointer) |
| 0x226040 | 0x810 | **Physical memory READ** |
| 0x226044 | 0x811 | **Physical memory WRITE** |
| 0x226080 | 0x820 | I/O port read (indexed, dword result) |
| 0x226084 | 0x821 | I/O port read (byte) |
| 0x2260C0 | 0x830 | I/O port/CR read (with index register) |
| 0x2260C4 | 0x831 | PCI config read (HalGetBusDataByOffset) |
| 0x226100 | 0x840 | I/O port write |
| 0x226104 | 0x841 | PCI config write (HalSetBusDataByOffset) |
| 0x226108 | 0x842 | PCI config read (byte) |
| 0x22610C | 0x843 | PCI config read (dword, indexed) |
| 0x226110 | 0x844 | PCI config write (byte, indexed) |
| 0x226114 | 0x845 | MSR/model-specific register operation |
| 0x226118 | 0x846 | Thread/event semaphore control |
| 0x226140 | 0x850 | I/O port write (dword) |
| 0x2261C4 | 0x871 | Kernel thread creation/management |
| 0x2261C8 | 0x872 | Worker thread parameter |
| 0x2261CC | 0x873 | Worker thread parameter |
| 0x2261D0 | 0x874 | Worker thread parameter |
| 0x2261D4 | 0x875 | Worker thread parameter |
| 0x2261D8 | 0x876 | Worker thread parameter |

---

## 5. Physical Memory Mechanism

### Method: MmMapIoSpace

The driver uses `MmMapIoSpace` to map physical addresses into kernel virtual address space,
performs the read/write operation, then unmaps with `MmUnmapIoSpace`.

```
MmMapIoSpace(
    PhysicalAddress,      // 64-bit, but only lower 32 bits populated
    NumberOfBytes,        // from IOCTL buffer size parameters
    CacheType = 0        // MmNonCached
);
```

### Serialization

All physical memory operations are serialized via a kernel semaphore:
- `KeWaitForSingleObject` before MmMapIoSpace
- `KeReleaseSemaphore` after MmUnmapIoSpace
- This prevents concurrent mapping conflicts but limits throughput

---

## 6. Range Restrictions

**NONE.**

The driver performs absolutely no validation of:
- Physical address value (any 32-bit address accepted)
- Size of read/write operation (any length accepted)
- Target region (no blacklist of MMIO, firmware, or protected areas)
- Caller identity or permissions (beyond initial handle open)

### Limitation: 32-bit Physical Address Only

```asm
and  dword ptr [rsp + 0x5c], 0    ; clear upper 32 bits
mov  dword ptr [rsp + 0x58], edi   ; store 32-bit phys addr
mov  rcx, qword ptr [rsp + 0x58]  ; load as 64-bit (upper = 0)
```

The physical address is stored as a DWORD and zero-extended. This means:
- **Maximum addressable**: 0xFFFFFFFF (4 GB)
- **Systems with >4GB RAM**: Cannot access physical memory above 4GB
- **Practical impact**: On a 16GB system, kernel structures above 4GB are unreachable

---

## 7. Detection

### Runtime Detection

```powershell
# Check if device exists
$handle = [IO.File]::Open("\\.\BS_RCIO", 'Open', 'Read', 'Read')

# Check service
Get-Service BS_RCIO64

# Registry
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\BS_RCIO64"
```

### Static Indicators

| Indicator | Value |
|-----------|-------|
| Device path | `\Device\BS_RCIO` |
| Symlink | `\DosDevices\BS_RCIO` |
| User path | `\\.\BS_RCIO` |
| Service name | BS_RCIO64 |
| SHA-256 | `d205286b...` |
| PDB string | `BS_RCIO64.pdb` |
| Version | 10.0.1901.1100 |
| Import combo | MmMapIoSpace + IoCreateDevice + HAL (small driver) |

---

## 8. toolkit Integration Assessment

### Viability: CONDITIONAL

**Advantages:**
- No range restrictions (unlike AsIO3's `g_goodRanges`)
- Simple, clean IOCTL interface
- Properly serialized (no race conditions)
- METHOD_BUFFERED (safe from user page faults)

**Critical Limitation:**
- **32-bit physical address only** - cannot access RAM above 4GB
- On modern systems with 8-32GB RAM, EPROCESS structures and AES key data
  frequently reside above the 4GB boundary
- This makes the driver **unreliable** for the VRChat key extraction use case

**Recommendation:**
- **Driver chain position**: LAST RESORT (after SIVX64, ASMMAP64)
- Only useful on systems with <= 4GB RAM or when target data is known to be in low memory
- The 32-bit limitation is a hard blocker for most real-world scenarios
- Consider using only for initial EPROCESS scanning (System process is often in low memory)
  then falling back to another driver for actual key reads if the target is in high memory
