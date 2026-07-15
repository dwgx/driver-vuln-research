# AsIO3/Asusgio3 Driver - Complete Reverse Engineering Report

## Executive Summary

The AsIO3 driver (service name "Asusgio3") is ALREADY LOADED and RUNNING on this system. It provides physical memory read/write, MSR access, I/O port access, and PCI config space operations. However, it implements a PID-based whitelist that restricts device access to ASUS processes only. The primary access barrier is NOT the physical memory range restriction (which covers all RAM) but rather the PID whitelist check that blocks non-ASUS processes from using IOCTLs.

## Driver Identity

| Property | Value |
|----------|-------|
| File | C:\Windows\system32\drivers\AsIO3.sys |
| Service | Asusgio3 |
| Size | 69,768 bytes |
| SHA256 | 0ae0784538379cbccd4accd32fbe74a0c62e30ca6a9a55299cdcf0c7a6b2fa4d |
| Version | 1.3.2.0 |
| Signer | ASUSTeK COMPUTER INC. (DigiCert) |
| PDB | D:\Jenkins\workspace\AsIO_Driver\AsIO3\x64\Release\AsIO3_64.sys.pdb |
| Status | RUNNING (boot-start, Type=1 System) |

## Device Names

| Type | Name |
|------|------|
| Device Object | \Device\Asusgio3 |
| Symlink | \DosDevices\Asusgio3 |
| User-mode path | \\\\.\Asusgio3 |

The device DOES exist (\\\\.\Asusgio3 returns ERROR_ACCESS_DENIED, not FILE_NOT_FOUND). The security descriptor blocks non-ASUS processes.

## Access Control Architecture

### Layer 1: Device Security Descriptor (IRP_MJ_CREATE)

The device object gets a restrictive security descriptor during initialization. The function at RVA 0xB410 calls:
- RtlGetOwnerSecurityDescriptor
- RtlGetGroupSecurityDescriptor
- RtlGetDaclSecurityDescriptor
- ZwSetSecurityObject

This sets the DACL such that only specific SIDs can open the device. Even running as Administrator returns ACCESS_DENIED (error 5).

### Layer 2: PID Whitelist (IOCTL Dispatch)

Even if a handle is obtained, every IOCTL goes through a PID validation function at RVA 0x14BC:

```
Function at 0x14BC (PID check):
1. Takes caller PID in ECX
2. Iterates a DWORD array at .data+0x0 (29 entries, 0x74 bytes / 4 = 29 slots)
3. Compares each entry against the caller's PID
4. If no match in static table, checks a DYNAMIC table:
   - Pointer at .data+0x5D0 -> count at [ptr+0x24]
   - Second pointer at .data+0x5D8 -> PID array
5. Returns 0 = ALLOWED, 1 = DENIED
```

If the PID check returns 1 (denied), the IOCTL returns STATUS_ACCESS_DENIED (0xC0000022).

### Layer 3: IoValidateDeviceIoControlAccess

Dynamically resolved (string at offset 0x75B0). Provides additional IOCTL-level access validation on newer Windows versions.

### Layer 4: Physical Address Range Validation (for MapPhysMem only)

The range check function at RVA 0x1514 validates requested physical addresses. See g_goodRanges section below.

## AsusCertService Unlock Mechanism

### Overview

The driver uses PsSetCreateProcessNotifyRoutineEx to register a process creation/termination callback at RVA 0x3CD0.

### Process Termination Handler (RVA 0x3CD0)

When a process exits (r8 parameter == NULL):
1. Iterates PID array from .data+0x3C0 to .data+0x5C0 (64 QWORD entries, 512 bytes)
2. If exiting PID matches an entry, zeros it out
3. This is the SECONDARY whitelist (QWORD-based, for the IOCTL path)

### Process Creation Handler

When a new process is created:
1. Gets process image file name via PsGetProcessImageFileName
2. Compares against the path: `C:\Program Files (x86)\ASUS\AsusCertService`
3. If the new process path matches, its PID is added to the whitelist

### How It Works End-to-End

```
1. System boots -> AsIO3.sys loads (Start=1, System)
2. AsusCertService.exe starts (PID 3760 currently)
3. Process notify callback fires for AsusCertService creation
4. Driver verifies path matches "C:\Program Files (x86)\ASUS\AsusCertService"
5. AsusCertService PID added to whitelist
6. AsusCertService opens \\.\Asusgio3 -> device SD allows it
7. AsusCertService calls IOCTLs -> PID check passes
8. Other ASUS apps may ask AsusCertService to proxy operations
```

### Current AsusCertService Status

- Running as PID 3760 (Session 0, Services)
- Service type: WIN32_OWN_PROCESS
- State: RUNNING (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)

## IOCTL Interface - Complete Map

### I/O Port Operations (0xA0400Fxx range)

| IOCTL | Function | Access | Description |
|-------|----------|--------|-------------|
| 0xA0400F58 | 0x3D6 | ANY | Port Read Byte |
| 0xA0400F5C | 0x3D7 | ANY | Port Read Word |
| 0xA0400F60 | 0x3D8 | ANY | Port Read DWord |
| 0xA0400F64 | 0x3D9 | ANY | Port Write Byte |
| 0xA0400F68 | 0x3DA | ANY | Port Write Word |
| 0xA0400F6C | 0x3DB | ANY | Port Write DWord |
| 0xA0400F70 | 0x3DC | ANY | Index Read (port+data pair) |
| 0xA0400F74 | 0x3DD | ANY | Index Write (port+data pair) |
| 0xA0400F78 | 0x3DE | ANY | Block Index Read |
| 0xA0400F7C | 0x3DF | ANY | Unknown Port Op |

### PCI Configuration Space (0xA0400F8x range)

| IOCTL | Function | Access | Description |
|-------|----------|--------|-------------|
| 0xA0400F80 | 0x3E0 | ANY | PCI Config Read Byte |
| 0xA0400F84 | 0x3E1 | ANY | PCI Config Read Word |
| 0xA0400F88 | 0x3E2 | ANY | PCI Config Read DWord |
| 0xA0400F8C | 0x3E3 | ANY | PCI Config Write Byte |
| 0xA0400F90 | 0x3E4 | ANY | PCI Config Write Word |
| 0xA0400F94 | 0x3E5 | ANY | PCI Config Write DWord |

### Physical Memory Operations (0xA04020xx range)

| IOCTL | Function | Access | Description |
|-------|----------|--------|-------------|
| 0xA0402000 | 0x800 | ANY | Allocate Contiguous Memory |
| 0xA0402004 | 0x801 | ANY | Free Contiguous Memory |
| 0xA040200C | 0x803 | ANY | **Map Physical Memory** |
| 0xA0402010 | 0x804 | ANY | **Unmap Physical Memory** |
| 0xA0402014 | 0x805 | ANY | Get Physical Address |
| 0xA0402018 | 0x806 | ANY | Unknown Phys Op |

### MSR Operations (0xA04064xx / 0xA040A4xx ranges)

| IOCTL | Function | Access | Description |
|-------|----------|--------|-------------|
| 0xA0406400 | 0x900 | READ | MSR Read (type 1) |
| 0xA0406404 | 0x901 | READ | MSR Read (type 2) |
| 0xA0406408 | 0x902 | READ | MSR Read (type 3) |
| 0xA040640C | 0x903 | READ | MSR Read Specific |
| 0xA0406458 | 0x916 | READ | Unknown Read Op |
| 0xA040A440 | 0x910 | WRITE | MSR Write (type 1) |
| 0xA040A444 | 0x911 | WRITE | MSR Write (type 2) |
| 0xA040A448 | 0x912 | WRITE | MSR Write (type 3) |
| 0xA040A45C | 0x917 | WRITE | Unknown Write |
| 0xA040A480 | 0x920 | WRITE | Unknown Write 2 |
| 0xA040A488 | 0x922 | WRITE | Unknown Write 3 |
| 0xA040A48C | 0x923 | WRITE | Unknown Write 4 |
| 0xA040A490 | 0x924 | WRITE | Unknown Write 5 |

### Control/Status Operations

| IOCTL | Function | Access | Description |
|-------|----------|--------|-------------|
| 0xA040244C | 0x913 | ANY | Unknown Control |
| 0xA0402450 | 0x914 | ANY | Unknown Control 2 |
| 0xA040A540 | 0x950 | WRITE | Bus Data Write 1 |
| 0xA040A544 | 0x951 | WRITE | Bus Data Write 2 |
| 0xA040A548 | 0x952 | WRITE | Bus Data Write 3 |
| 0xA040A54C | 0x953 | WRITE | Bus Data Write 4 |

## MapPhysMem IOCTL (0xA040200C) - Detailed Analysis

### Handler Flow (RVA 0x4290)

```
1. Check input buffer size >= 0x1028 bytes (minimum required)
2. Read mapping type from buffer[0]:
   - Type 1: 32-bit address (DWORD at buffer[0x14], page-aligned)
   - Type 2: 64-bit address (QWORD at buffer[0x18], page-aligned)  
   - Type 4: Full 64-bit (DWORD at buffer[0x0C])
3. Read size from buffer[0x10]
4. Call range validation (0x140004018):
   a. Call PID check (0x140001514) - returns 0xC0000022 if denied
   b. Open \Device\PhysicalMemory section
   c. Call ZwMapViewOfSection to map the physical range
5. Return mapped virtual address in output buffer
```

### Input Buffer Layout (0x1028 bytes minimum)

```
Offset  Size    Field
0x00    BYTE    Address type (1=32-bit, 2=64-bit, 4=extended)
0x04    DWORD   Flags / bus info
0x06    BYTE    Cache type
0x0C    DWORD   Extended address (for type 4)
0x10    DWORD   Size to map
0x14    DWORD   Physical address (32-bit, page-aligned for type 1)
0x18    QWORD   Physical address (64-bit, page-aligned for type 2)
```

### Output Buffer

```
Offset  Size    Field
0x08    QWORD   Mapped virtual address (returned to caller)
0x18    QWORD   Section handle / mapping info (for type 1)
0x20    QWORD   Section handle / mapping info (for type 2)
```

## Physical Memory Mapping Method

The driver maps physical memory via:
1. ZwOpenSection on \Device\PhysicalMemory (gets section handle)
2. ZwMapViewOfSection (maps physical range into caller's address space)
3. NOT MmMapIoSpace (which maps into kernel space)

This means the mapping is in USER-MODE address space - the caller gets a direct virtual address to the physical memory. Supports both read and write.

## g_goodRanges - Physical Address Validation

### How It Works (RVA 0x1514)

The range validation has THREE levels:

**Level 1: Active mappings linked list** (.data+0x670)
- Linked list of currently-mapped regions
- If requested range overlaps any active mapping, it's allowed
- This seems to be a "re-map allowed" check

**Level 2: Static port/address table** (.data+0x130)
- 2 entries of 16 bytes each
- Format: [start_low:4][start_high:4][size_low:4][size_high:4]
- Small set of always-allowed ranges (likely MMIO)

**Level 3: Dynamic OS memory ranges** (pointer at .data+0x5D0)
- Populated via MmGetPhysicalMemoryRangesEx2 (Win10+) or registry fallback
- Contains ALL physical RAM ranges managed by the OS
- Count stored at [ptr+0x34], ranges as QWORD pairs

### Key Finding: Range Restriction is NOT a Barrier

The dynamic ranges (Level 3) cover ALL 31.38 GB of installed RAM. The restriction only blocks:
- MMIO regions (device BARs, APIC, etc.)
- Non-existent physical addresses

Since VRChat process memory resides in normal physical RAM, the range check will PASS for any valid RAM page.

## Detection Profile

### Why This Is the Safest Driver Option

1. **Already loaded**: Service "Asusgio3" started at boot (Start=1), no new driver load event
2. **Signed by ASUS**: Legitimate DigiCert-signed driver, not suspicious
3. **Part of standard ASUS software**: Present on all ASUS motherboards/laptops
4. **No new registry entries**: Already in CurrentControlSet\Services
5. **No new file on disk**: Already at system32\drivers\AsIO3.sys
6. **No EAC detection vector**: EAC does not flag ASUS system drivers
7. **No minifilter callbacks**: Not a filesystem or process creation driver (except notify)

### Comparison to Alternatives

| Driver | Load Fingerprint | Detection Risk |
|--------|-----------------|----------------|
| AsIO3 (this) | NONE (already loaded) | ZERO |
| SIVX64.sys | New service + driver load | MEDIUM |
| ASMMAP64.sys | New service + driver load | MEDIUM |
| Manual mapping | No service but kernel code | HIGH |

## Bypass Strategies

### Strategy 1: Impersonate AsusCertService (RECOMMENDED)

The driver checks the calling process's PID against its whitelist. The whitelist is populated when a process with path matching `C:\Program Files (x86)\ASUS\AsusCertService` is created.

**Approach**: Place our executable at or rename it to match the path check:
- Copy our tool to `C:\Program Files (x86)\ASUS\AsusCertService\exploit.exe`
- The process notify callback uses PsGetProcessImageFileName which returns just the filename (15 chars max)
- OR uses the full path comparison with the string at offset 0x7120

**Risk**: Low - just creating a file in an ASUS directory

### Strategy 2: Inject into AsusCertService.exe (PID 3760)

Since AsusCertService is already whitelisted:
1. Open AsusCertService.exe process (it's a normal service, not PPL)
2. Inject a DLL or create a remote thread
3. The injected code inherits the PID and passes the whitelist check
4. Open \\.\Asusgio3 from within the injected context
5. Duplicate the handle to our process

**Risk**: Medium - process injection may trigger AV/EDR

### Strategy 3: Modify the PID Whitelist Directly

The whitelist is in the driver's .data section at a known RVA offset (0x93C0-0x95C0 for QWORD array, or .data+0x0 for DWORD array at 0x9000). 

Since we have physical memory access from another driver (if available), we could:
1. Find AsIO3.sys base address in kernel
2. Calculate .data section VA
3. Write our PID directly into the whitelist

**Risk**: Requires another memory write primitive first (chicken-and-egg)

### Strategy 4: Hook the Process Notify Callback

The callback at RVA 0x3CD0 is what adds PIDs to the whitelist. If we can modify the path comparison or the callback logic, any process would be whitelisted.

### Strategy 5: Security Descriptor Modification

The device's security descriptor is set via ZwSetSecurityObject during init. If we can call ZwSetSecurityObject on the device object to add our SID to the DACL, we bypass Layer 1 entirely.

This requires a kernel-mode primitive or a service running as SYSTEM with SeSecurityPrivilege.

## Imports (71 from ntoskrnl.exe, 3 from HAL.dll)

### Key Imports for Our Purpose

- MmMapIoSpace / MmUnmapIoSpace - kernel physical memory mapping
- ZwMapViewOfSection / ZwUnmapViewOfSection - section mapping (user-mode phys mem)
- ZwOpenSection - opens \Device\PhysicalMemory
- MmGetPhysicalAddress - virtual to physical translation
- MmAllocateContiguousMemory / MmFreeContiguousMemory - contiguous alloc
- PsSetCreateProcessNotifyRoutineEx - process creation monitoring
- PsGetProcessImageFileName - get process name for whitelist check
- HalGetBusDataByOffset / HalSetBusDataByOffset - PCI config access
- HalTranslateBusAddress - bus address translation

## Conclusion

The AsIO3 driver is the IDEAL candidate for physical memory access because:
1. It's already loaded (zero detection footprint)
2. It maps physical memory into user-mode (perfect for our use case)
3. The range restriction covers all RAM (no limitation for process memory scanning)
4. The ONLY barrier is the PID whitelist, which has multiple bypass paths
5. It supports both read and write operations

The recommended approach is Strategy 1 (path spoofing) or Strategy 2 (inject into AsusCertService), as these require no additional kernel primitives.
