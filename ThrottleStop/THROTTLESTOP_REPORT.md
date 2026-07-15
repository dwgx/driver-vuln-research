# ThrottleStop.sys Static Reverse Engineering Report

## Executive Summary

ThrottleStop.sys (v3.0.0.0) is a signed kernel driver by TechPowerUp LLC shipped with the ThrottleStop CPU throttling utility. It exposes arbitrary physical memory read/write, MSR read/write, I/O port access, and PCI config space operations through 11 distinct IOCTL handlers. The driver's only access control is an SDDL limiting device open to SYSTEM and Administrators -- any admin-level process can exploit it for full kernel-level primitives without loading unsigned code.

CVE: CVE-2025-7771
CWE: CWE-782 (Exposed IOCTL with Insufficient Access Control)

---

## 1. PE Metadata

| Field | Value |
|-------|-------|
| SHA-256 | `16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0` |
| Architecture | x86-64 (AMD64) |
| File Size | 50,216 bytes |
| Compile Time | 2020-10-06 22:34:27 UTC (0x5F7CD4D3) |
| ImageBase | 0x140000000 |
| EntryPoint RVA | 0x1730 |
| Subsystem | Native (1) |
| Sections | 8 (.text, .rdata, .data, .pdata, PAGE, INIT, .rsrc, .reloc) |
| Signing | Dual-signed (SHA-1 + SHA-256), DigiCert EV Code Signing |
| Signer | TechPowerUp LLC, Spokane WA (EIN: 604 057 982) |
| Product | "Low-Level Driver" |
| Copyright | 2004-2020 |
| PDB | Driver.pdb |

---

## 2. Imports

### ntoskrnl.exe (51 imports)

Critical imports for exploitation:
- `MmMapIoSpace` / `MmUnmapIoSpace` -- physical memory mapping
- `MmMapLockedPagesSpecifyCache` -- maps kernel pages to user-mode
- `IoAllocateMdl` / `MmBuildMdlForNonPagedPool` / `IoFreeMdl` -- MDL management
- `MmUnmapLockedPages` -- unmap from user space
- `PsGetCurrentProcessId` -- PID tracking for mappings
- `IoCreateDevice` -- device creation
- `MmGetSystemRoutineAddress` -- dynamic function resolution (IoCreateDeviceSecure)

Security-relevant:
- `ObOpenObjectByPointer`, `ZwSetSecurityObject` -- security descriptor management
- `RtlCreateSecurityDescriptor`, `RtlSetDaclSecurityDescriptor` -- DACL construction
- `SeCaptureSecurityDescriptor`, `SeExports`

### HAL.dll (2 imports)
- `HalGetBusDataByOffset` -- PCI config read
- `HalSetBusDataByOffset` -- PCI config write

---

## 3. Device & Access Control

### Device Creation

The driver dynamically resolves `IoCreateDeviceSecure` via `MmGetSystemRoutineAddress` and creates the device with:

| Parameter | Value |
|-----------|-------|
| DeviceType | 0x22 (FILE_DEVICE_UNKNOWN) |
| DeviceExtensionSize | 0x2818 (10,264 bytes) |
| DeviceCharacteristics | 0x100 (FILE_DEVICE_SECURE_OPEN) |
| Exclusive | FALSE |
| SDDL | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` |

### Device Name

The device name is derived from the registry service path at runtime. For the standard ThrottleStop service registration:
- Device: `\Device\ThrottleStop`
- Symlink: `\??\ThrottleStop`
- User-mode path: `\\.\ThrottleStop`

### Access Control Analysis

**SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` means:**
- `D:P` -- DACL present, protected
- `(A;;GA;;;SY)` -- Allow Generic All to SYSTEM
- `(A;;GA;;;BA)` -- Allow Generic All to Built-in Administrators

**Verdict:** Any process running as Administrator (or SYSTEM) can open the device and issue IOCTLs. No per-IOCTL authorization check exists. The IRP_MJ_CREATE handler simply increments a reference counter and returns STATUS_SUCCESS -- zero additional validation.

### IRP_MJ_CREATE (0x140001AA0)

```
lock inc [DeviceExtension + 0x08]  ; increment open count
mov IoStatus.Status = 0            ; STATUS_SUCCESS
mov IoStatus.Information = 0
IofCompleteRequest(Irp, 0)
return STATUS_SUCCESS
```

No caller validation, no token check, no integrity level check.

---

## 4. IOCTL Interface

### Dispatch Mechanism

The DeviceIoControl handler at 0x140001EF0 uses a two-level jump table:
- Base IOCTL: 0x80006430
- Range: 0x80006430 -- 0x800064A4 (117 entries, 0x75 span)
- Active handlers: 11 unique dispatch targets
- Remaining 106 codes route to a "not implemented" return (STATUS_SUCCESS with no op)

### IOCTL Code Decoding

All IOCTLs use: DeviceType=0x8000 (custom), Method=METHOD_BUFFERED (0)

| IOCTL Code | Function | Handler Address |
|------------|----------|-----------------|
| 0x80006430 | I/O Port Read | 0x140001F4E |
| 0x80006434 | I/O Port Write | 0x140001FC0 |
| 0x80006448 | MSR Read (RDMSR) | 0x140001CB0 |
| 0x8000644C | MSR Write (WRMSR) | 0x140001C10 |
| 0x8000645C | Physical Memory Map to User | 0x140001D30 |
| 0x80006460 | Physical Memory Unmap | 0x140002064 |
| 0x80006494 | Get Mapping Count | 0x140002127 |
| 0x80006498 | Physical Memory Read | 0x140002184 |
| 0x8000649C | Physical Memory Write | 0x140002271 |
| 0x800064A0 | PCI Config Read | 0x140002365 |
| 0x800064A4 | PCI Config Write | 0x140002405 |

---

## 5. Physical Memory Primitives (Primary Exploitation Surface)

### IOCTL 0x80006498 -- Physical Memory Read

**Input:** 8-byte physical address
**Output:** 8 bytes of data read from physical memory
**Size:** Controlled by InputBufferLength field (1, 2, 4, or 8 bytes)

Flow:
1. Validate OutputBufferLength == 8
2. Read size from `IO_STACK_LOCATION.Parameters.DeviceIoControl.InputBufferLength` field byte
3. Call `MmMapIoSpace(PhysAddr, Size, MmNonCached=0)` -- **NO RANGE CHECK**
4. Read 1/2/4/8 bytes from mapped kernel VA
5. Call `MmUnmapIoSpace` to release
6. Return data in output buffer

### IOCTL 0x8000649C -- Physical Memory Write

**Input:** 8-byte physical address + data (8+ bytes total depending on size)
**Output:** None
**Size:** Controlled by OutputBufferLength field byte

Flow:
1. Validate InputBufferLength != 0
2. Read size indicator (1, 2, 4, or 8)
3. Call `MmMapIoSpace(PhysAddr, Size, MmNonCached=0)` -- **NO RANGE CHECK**
4. Write 1/2/4/8 bytes to mapped kernel VA
5. Call `MmUnmapIoSpace` to release

### IOCTL 0x8000645C -- Physical Memory Map to User Space

**Input:** 12 bytes (PhysicalAddress:8 + Size:4)
**Output:** 4 or 8 byte user-mode virtual address
**Capability:** Persistent mapping of arbitrary physical ranges into calling process

Flow:
1. Validate input/output buffer sizes
2. `MmMapIoSpace(PhysAddr, Size, 0)` -- maps to kernel VA, **NO RANGE CHECK**
3. `IoAllocateMdl(KernelVA, Size, 0, 0, 0)` -- create MDL
4. `MmBuildMdlForNonPagedPool(Mdl)` -- describe pages
5. `MmMapLockedPagesSpecifyCache(Mdl, UserMode, MmCached, 0, 0, NormalPagePriority|0x10)`
   -- **Maps physical memory into USER-MODE address space**
6. Store in mapping table (max 256 entries) with PID for cleanup
7. Return user-mode pointer

This is the most powerful primitive -- it gives the caller a direct user-mode window into arbitrary physical memory that persists until explicitly unmapped or the process exits.

### IOCTL 0x80006460 -- Unmap Physical Memory

Searches the 256-entry mapping table for matching address + PID, then unmaps.

---

## 6. MSR Primitives

### IOCTL 0x80006448 -- MSR Read

**Input:** 4-byte MSR index
**Output:** 8-byte MSR value
**Validation:** NONE on MSR index

Directly executes the `RDMSR` instruction with the user-supplied register index.

### IOCTL 0x8000644C -- MSR Write

**Input:** 12 bytes (MSR_index:4 + Value:8)
**Output:** None

**Partial validation:** Blocks writes to:
- 0xC0000080-0xC0000082 (IA32_EFER, IA32_STAR, IA32_LSTAR) -- prevents SMEP/SMAP toggle and SYSCALL hooking
- 0x174-0x176 (IA32_SYSENTER_CS/ESP/EIP) -- prevents SYSENTER hooking

All other MSR writes are unrestricted. This still allows:
- Disabling hardware prefetch, cache configuration changes
- Power management manipulation (the intended use case)
- CR4 shadow manipulation on some platforms

---

## 7. I/O Port Primitives

### IOCTL 0x80006430 -- Port Read

Executes `IN` (byte/word/dword) on any I/O port. No port validation.

### IOCTL 0x80006434 -- Port Write

Executes `OUT` (byte/word/dword) to any I/O port. No port validation.

These can be used to interact with hardware directly (PCI, ACPI, chipset registers, embedded controllers).

---

## 8. PCI Config Space

### IOCTL 0x800064A0 -- PCI Config Read

Calls `HalGetBusDataByOffset` with user-supplied bus/device/function/offset.

### IOCTL 0x800064A4 -- PCI Config Write

Calls `HalSetBusDataByOffset` with user-supplied parameters.

---

## 9. Exploitation for toolkit

### Physical Memory R/W for AES Key Extraction

The Read (0x80006498) and Write (0x8000649C) IOCTLs provide the exact primitives needed:

1. **EPROCESS Walk:** Read physical memory at known kernel offsets to traverse ActiveProcessLinks
2. **Page Table Walk:** Read CR3 (DirectoryTableBase) from EPROCESS, then walk PML4/PDPT/PD/PT
3. **AES Key Scan:** Scan VRChat process physical pages for 16-byte key patterns
4. **PPL Bypass:** Write 0x00 to EPROCESS.Protection offset to remove PPL from VRChat

### Advantages Over Current Drivers

| Feature | SIVX64 | ThrottleStop |
|---------|--------|--------------|
| Signed | Cross-signed only | EV Code Signed (DigiCert) |
| Access | Custom IOCTL | Standard DeviceIoControl |
| Range check | Yes (via g_goodRanges) | **NONE** |
| User-mode map | No | Yes (persistent) |
| MSR access | No | Yes |
| Detection risk | Known to EDR | Less flagged (legitimate tool) |

### PPL Bypass Workflow

```
1. Open \\.\ThrottleStop (requires admin)
2. Use NtQuerySystemInformation to get kernel base
3. Use Superfetch (NtQueryVirtualMemory) for VA-to-PA translation
4. Read PsInitialSystemProcess PA -> get System EPROCESS VA
5. Walk ActiveProcessLinks to find VRChat EPROCESS
6. Write 0x00 to EPROCESS + 0x87A (Protection field)
7. VRChat is now unprotected -- read its memory normally
```

---

## 10. Detection

| Indicator | Value |
|-----------|-------|
| Device name | `\\.\ThrottleStop` |
| Service name | `ThrottleStop` |
| SHA-256 | `16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0` |
| Signer | TechPowerUp LLC |
| LOLDrivers | Listed (loldrivers.io) |
| BYOVD category | Physical memory R/W, MSR, I/O port |

---

## 11. Risk Assessment

| Category | Rating |
|----------|--------|
| Privilege required | Administrator |
| Exploitation complexity | Low |
| Range validation | NONE (physical memory) |
| User-mode mapping | YES (persistent) |
| Anti-cheat risk | Lower than SIVX64 (legitimate software driver) |
| Signing validity | Valid EV certificate (may be revoked) |
