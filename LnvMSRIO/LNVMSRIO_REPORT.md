# LnvMSRIO.sys Static Reverse Engineering Report

## CVE-2025-8061 | Lenovo Physical Memory / MSR / IO Port Driver

---

## 1. Executive Summary

LnvMSRIO.sys is a signed Lenovo kernel driver that provides unrestricted access to:
- **Physical memory** (read/write via MmMapIoSpace)
- **Model-Specific Registers** (RDMSR/WRMSR)
- **I/O Ports** (IN/OUT byte/word/dword)
- **PCI Configuration Space** (HalGetBusDataByOffset/HalSetBusDataByOffset)
- **Performance Counters** (RDPMC)
- **CPU Halt** (HLT instruction)

The device `\\Device\\WinMsrDev` has **NO access control** on IRP_MJ_CREATE. Any process with a handle can send IOCTLs. Combined with the Microsoft-signed certificate, this is a complete kernel compromise primitive.

---

## 2. PE Metadata

| Property | Value |
|----------|-------|
| File Size | 50,216 bytes |
| MD5 | `e2b952939b8e9d76cff7d130b797a74d` |
| SHA256 | `245b6ab442a7d53dc30ece28e1c6de727c019669385877cbe929b81aa1a2ad2f` |
| Architecture | x86-64 (AMD64) |
| Subsystem | Native (1) |
| Entry Point RVA | 0x00002C40 |
| Image Base | 0x0000000140000000 |
| Timestamp | 0x6707686A (2024-10-10) |
| PDB Path | `D:\Work\01.Dispatcher\GitLab\process_management\x64\Release\LnvMSRIO.pdb` |
| File Version | 3.1.0.35 |
| Company | Lenovo |
| Description | Lenovo filter driver |
| Copyright | Copyright (C) 2024, Lenovo. All Rights Reserved |

### Sections

| Name | VirtAddr | VirtSize | RawSize | Characteristics |
|------|----------|----------|---------|-----------------|
| .text | 0x1000 | 0x273D | 0x2800 | RWX (code) |
| .rdata | 0x4000 | 0x0BAC | 0x0C00 | R (read-only data) |
| .data | 0x5000 | 0x0308 | 0x0200 | RW (data) |
| .pdata | 0x6000 | 0x0240 | 0x0400 | R (exception data) |
| INIT | 0x7000 | 0x0522 | 0x0600 | RX (discardable) |
| .rsrc | 0x8000 | 0x0380 | 0x0400 | R (resources) |
| .reloc | 0x9000 | 0x0034 | 0x0200 | R (relocations) |

### Function Count

48 functions (from .pdata RUNTIME_FUNCTION entries)

---

## 3. Imports

### FLTMGR.SYS (Minifilter Framework)
- FltRegisterFilter
- FltUnregisterFilter
- FltStartFiltering
- FltCreateCommunicationPort
- FltCloseCommunicationPort
- FltCloseClientPort
- FltSendMessage
- FltBuildDefaultSecurityDescriptor
- FltFreeSecurityDescriptor

### ntoskrnl.exe (Kernel)
- IoCreateDevice
- IoDeleteDevice
- IoCreateSymbolicLink
- IoDeleteSymbolicLink
- IofCompleteRequest
- **MmMapIoSpace** (physical memory mapping)
- **MmUnmapIoSpace** (unmap)
- ProbeForRead
- ProbeForWrite
- ExAllocatePool2
- ExFreePoolWithTag
- RtlInitUnicodeString
- RtlCopyUnicodeString
- DbgPrintEx
- PsSetCreateProcessNotifyRoutineEx
- PoRegisterPowerSettingCallback
- PoUnregisterPowerSettingCallback
- ZwPowerInformation
- __C_specific_handler

### HAL.dll
- **HalGetBusDataByOffset** (PCI config read)
- **HalSetBusDataByOffset** (PCI config write)

### WDFLDR.SYS (WDF Loader)
- WdfVersionBind / WdfVersionUnbind
- WdfLdrQueryInterface
- WdfVersionBindClass / WdfVersionUnbindClass

---

## 4. Named Objects & Strings

| Type | Value |
|------|-------|
| Device | `\Device\WinMsrDev` |
| Symlink | `\DosDevices\WinMsrDev` |
| Minifilter Port | `\LnvMiniFilterDriverPort` |
| Service Name | `LnvMSRIO` |
| Internal Tags | "Lenovo0", "Lenovo1" |

Usermode path: `\\.\WinMsrDev`

---

## 5. Access Control Analysis

### IRP_MJ_CREATE Handler (Device Open)

The dispatch function at `0x140001580` handles IRP major function codes via a byte comparison:

```
byte 0x00 = IRP_MJ_CREATE  -> increment reference counter, return STATUS_SUCCESS
byte 0x02 = IRP_MJ_CLOSE   -> decrement reference counter, return STATUS_SUCCESS
byte 0x0E = IRP_MJ_DEVICE_CONTROL -> IOCTL dispatch
```

**There is NO access control on device open.** No SID check, no process validation, no ACL enforcement. The counter at `[rip+0x3AD1]` is compared to -1 (unlimited opens allowed).

### Minifilter Port Security

The driver creates `\LnvMiniFilterDriverPort` using `FltBuildDefaultSecurityDescriptor`, which typically grants access to administrators. However, the main device `\Device\WinMsrDev` has no such restriction.

---

## 6. IOCTL Interface (Complete)

Device type: 0x9C40 (custom). All IOCTLs use METHOD_BUFFERED or METHOD_NEITHER.

### IOCTL Decode

| IOCTL Code | DevType | Access | Function | Method | Purpose |
|------------|---------|--------|----------|--------|---------|
| 0x9C402000 | 0x9C40 | R | 0x800 | BUFFERED | Get Version (returns 0x1000000) |
| 0x9C402004 | 0x9C40 | R | 0x801 | BUFFERED | Get Reference Count |
| 0x9C402084 | 0x9C40 | R | 0x821 | BUFFERED | **MSR READ** (RDMSR) |
| 0x9C402088 | 0x9C40 | R | 0x822 | BUFFERED | **MSR WRITE** (WRMSR) |
| 0x9C40208C | 0x9C40 | R | 0x823 | BUFFERED | **PCI Config Read** (HalGetBusData) |
| 0x9C402090 | 0x9C40 | R | 0x824 | BUFFERED | **HLT** (CPU Halt) |
| 0x9C4060C4 | 0x9C40 | RW | 0x831 | NEITHER | IO Port Operation (sub-dispatched) |
| 0x9C4060CC | 0x9C40 | RW | 0x833 | NEITHER | **IO Port Read BYTE** |
| 0x9C4060D0 | 0x9C40 | RW | 0x834 | NEITHER | **IO Port Read WORD** |
| 0x9C4060D4 | 0x9C40 | RW | 0x835 | NEITHER | **IO Port Read DWORD** |
| 0x9C406104 | 0x9C40 | RW | 0x841 | BUFFERED | **Physical Memory READ** |
| 0x9C406144 | 0x9C40 | RW | 0x851 | BUFFERED | **PCI Config Read (alt)** |
| 0x9C40A0C8 | 0x9C40 | W | 0x832 | NEITHER | IO Port Operation (sub-dispatched) |
| 0x9C40A0D8 | 0x9C40 | W | 0x836 | NEITHER | **IO Port Write BYTE** |
| 0x9C40A0DC | 0x9C40 | W | 0x837 | NEITHER | **IO Port Write WORD** |
| 0x9C40A0E0 | 0x9C40 | W | 0x838 | NEITHER | **IO Port Write DWORD** |
| 0x9C40A108 | 0x9C40 | W | 0x842 | BUFFERED | **Physical Memory WRITE** |
| 0x9C40A148 | 0x9C40 | W | 0x852 | BUFFERED | **PCI Config Write** (HalSetBusData) |
| 0x9C402270 | 0x9C40 | R | 0x89C | BUFFERED | **RDPMC** (perf counter read) |

---

## 7. Input/Output Structure Definitions

### Physical Memory Read (IOCTL 0x9C406104)

```c
// Input: exactly 16 bytes (METHOD_BUFFERED)
struct PhysMemReadInput {
    UINT64 PhysicalAddress;   // +0x00: target physical address
    UINT32 AccessSize;        // +0x08: element size (1=BYTE, 2=WORD, 8=QWORD)
    UINT32 Count;             // +0x0C: number of elements to read
};
// Total read size = AccessSize * Count

// Output: buffer receives (AccessSize * Count) bytes
```

### Physical Memory Write (IOCTL 0x9C40A108)

```c
// Input: 16-byte header + data (METHOD_BUFFERED)
struct PhysMemWriteInput {
    UINT64 PhysicalAddress;   // +0x00: target physical address
    UINT32 AccessSize;        // +0x08: element size (1=BYTE, 2=WORD, 8=QWORD)
    UINT32 Count;             // +0x0C: number of elements
    UINT8  Data[];            // +0x10: data to write (AccessSize * Count bytes)
};
// InputBufferLength must be >= 16 + (AccessSize * Count)
```

### MSR Read (IOCTL 0x9C402084)

```c
// Input: 4 bytes
struct MsrReadInput {
    UINT32 MsrIndex;          // +0x00: MSR register number
};

// Output: 8 bytes
struct MsrReadOutput {
    UINT64 Value;             // +0x00: 64-bit MSR value (EDX:EAX)
};
```

### MSR Write (IOCTL 0x9C402088)

```c
// Input: 12 bytes
struct MsrWriteInput {
    UINT32 MsrIndex;          // +0x00: MSR register number
    UINT64 Value;             // +0x04: 64-bit value to write (unaligned!)
};

// Output: 4 bytes (returns 0 on success)
```

### IO Port Read (IOCTL 0x9C4060CC/D0/D4)

```c
// Input: 4 bytes
struct IoPortReadInput {
    UINT32 PortNumber;        // +0x00: I/O port address (0x0000-0xFFFF)
};

// Output:
// 0x9C4060CC: 1 byte (IN AL, DX)
// 0x9C4060D0: 2 bytes (IN AX, DX)
// 0x9C4060D4: 4 bytes (IN EAX, DX)
```

### IO Port Write (IOCTL 0x9C40A0D8/DC/E0)

```c
// Input:
struct IoPortWriteInput {
    UINT32 PortNumber;        // +0x00: I/O port address
    UINT32 Value;             // +0x04: value to write (byte/word/dword)
};
```

### PCI Config Read (IOCTL 0x9C406144 / 0x9C40208C)

```c
// Input: 8 bytes
struct PciConfigReadInput {
    UINT32 BDF;               // +0x00: Bus/Device/Function encoded
                              //   bits[15:8] = Bus number
                              //   bits[7:3]  = Device number
                              //   bits[2:0]  = Function number
    UINT32 Offset;            // +0x04: register offset
};

// IOCTL 0x9C406144: uses HalGetBusDataByOffset (full read)
// IOCTL 0x9C40208C: uses RDPMC (possibly mislabeled in binary)
```

### PCI Config Write (IOCTL 0x9C40A148)

```c
// Input: 8+ bytes
struct PciConfigWriteInput {
    UINT32 BDF;               // +0x00: Bus/Device/Function
    UINT32 Offset;            // +0x04: register offset
    UINT8  Data[];            // +0x08: data to write
};
```

---

## 8. Physical Memory Mechanism

The driver uses **MmMapIoSpace** to map physical memory into kernel virtual address space:

```
1. Extract PhysicalAddress from input buffer [+0x00]
2. Calculate total_size = AccessSize * Count
3. Call MmMapIoSpace(PhysicalAddress, total_size, MmNonCached)
4. Switch on AccessSize:
   - 1 (BYTE):  copy bytes individually via helper at 0x140001E80
   - 2 (WORD):  copy words via helper at 0x140001EE0
   - 8 (QWORD): copy qwords via helper at 0x140001EB0
5. Call MmUnmapIoSpace(mapped_va, total_size)
6. Return data in output buffer
```

For writes, the same pattern but data flows from input buffer (offset +0x10) into the mapped region.

---

## 9. MSR Access

### RDMSR (0x9C402084)

```asm
mov rax, [rsp+0x40]    ; input buffer
mov ecx, [rax]         ; MSR index from input[0]
rdmsr                  ; result in EDX:EAX
shl rdx, 0x20
or  rax, rdx           ; combine to 64-bit
; copy 8 bytes to output buffer
```

### WRMSR (0x9C402088)

```asm
mov rax, [rsp+0x20]    ; input buffer
mov rdx, [rax+4]       ; 64-bit value from input[4] (unaligned)
mov rax, rdx
shr rdx, 0x20          ; high 32 bits to EDX
mov rcx, [rsp]         ; MSR index
mov ecx, [rcx]         ; from input[0]
wrmsr                  ; write ECX=index, EDX:EAX=value
```

**No MSR index validation.** Any MSR can be read or written.

---

## 10. Range Restrictions

**NONE.**

- No physical address whitelist or blacklist
- No MSR index validation
- No I/O port restrictions
- No PCI BDF filtering
- No size limits beyond buffer size validation

The only validation performed:
- Input/output buffer pointer != NULL
- Input buffer size == expected size (e.g., 16 for phys read)
- Output buffer size >= expected output size

---

## 11. Detection Profile

| Artifact | Value |
|----------|-------|
| Device Name | `\Device\WinMsrDev` |
| Symbolic Link | `\DosDevices\WinMsrDev` |
| Usermode Path | `\\.\WinMsrDev` |
| Service Name | `LnvMSRIO` |
| Minifilter Port | `\LnvMiniFilterDriverPort` |
| Registry Key | `HKLM\System\CurrentControlSet\Services\LnvMSRIO` |
| File Name | `LnvMSRIO.sys` |
| PDB Fingerprint | `process_management` project |
| File Hash (SHA256) | `245b6ab442a7d53dc30ece28e1c6de727c019669385877cbe929b81aa1a2ad2f` |

---

## 12. Comparison with Other Drivers

| Feature | LnvMSRIO | SIVX64 | ASMMAP64 | AsIO3 |
|---------|----------|--------|----------|-------|
| Phys Mem R/W | YES (unrestricted) | YES | YES | YES (range-limited) |
| MSR R/W | YES | NO | NO | NO |
| IO Ports | YES | NO | NO | YES |
| PCI Config | YES | NO | NO | NO |
| Access Control | NONE | NONE | NONE | Process check |
| Range Limits | NONE | NONE | NONE | g_goodRanges |
| Signed | YES (Lenovo) | YES | YES | YES |

**LnvMSRIO is the most capable driver in the collection.** It provides every hardware primitive needed with zero restrictions.

---

## 13. Exploitation for toolkit

### Advantages over Current Drivers

1. **No range restrictions** - Unlike AsIO3, can access any physical address
2. **MSR access** - Can read IA32_LSTAR (syscall handler), modify CR3, etc.
3. **Simple IOCTL interface** - Straightforward 16-byte input structure
4. **Signed by Lenovo** - Less suspicious than hardware monitor drivers
5. **Multiple primitives** - Single driver covers all needs

### Recommended Usage for AES Key Extraction

```
1. Load LnvMSRIO.sys via NtLoadDriver
2. Open \\.\WinMsrDev
3. Use IOCTL 0x9C406104 to scan VRChat process physical pages
4. Pattern: scan for 16-byte AES keys in known memory regions
5. Alternative: read CR3 via MSR, walk page tables physically
```

### Risk Assessment

- EAC detection: LOW (Lenovo utility driver, not in known blocklists as of analysis date)
- HVCI/VBS: MmMapIoSpace may be blocked on HVCI-enabled systems
- Microsoft blocklist: Check latest driver blocklist before use

---

## 14. Additional Capabilities

### Process Notification (PsSetCreateProcessNotifyRoutineEx)

The driver registers a process creation callback, suggesting it monitors which processes start. This could be used for:
- Detecting when VRChat starts
- Auto-triggering key extraction

### Power Management (PoRegisterPowerSettingCallback)

Monitors power state changes. Likely used for suspending hardware access during sleep/hibernate.

### Minifilter (FltRegisterFilter)

Registers as a filesystem minifilter. Purpose unclear from static analysis - may monitor file access to protect itself or log operations.

---

## 15. Verified IOCTL Summary Table

| IOCTL | Handler RVA | Operation | Input Size | Output Size |
|-------|-------------|-----------|------------|-------------|
| 0x9C402000 | inline | Version query | 0 | 4 |
| 0x9C402004 | inline | Ref count | 0 | 4 |
| 0x9C402084 | 0x140002140 | RDMSR | 4 | 8 |
| 0x9C402088 | 0x140002680 | WRMSR | 12 | 4 |
| 0x9C40208C | 0x140002270 | RDPMC | 4 | 8 |
| 0x9C402090 | inline (HLT) | CPU Halt | 0 | 0 |
| 0x9C4060CC | 0x140001F10 | IN byte | 4 | 1 |
| 0x9C4060D0 | 0x140001F10 | IN word | 4 | 2 |
| 0x9C4060D4 | 0x140001F10 | IN dword | 4 | 4 |
| 0x9C406104 | 0x140001FE0 | Phys Read | 16 | variable |
| 0x9C406144 | 0x1400021D0 | PCI Read | 8 | variable |
| 0x9C40A0D8 | 0x140002440 | OUT byte | 8 | 0 |
| 0x9C40A0DC | 0x140002440 | OUT word | 8 | 0 |
| 0x9C40A0E0 | 0x140002440 | OUT dword | 8 | 0 |
| 0x9C40A108 | 0x140002500 | Phys Write | 16+data | 0 |
| 0x9C40A148 | 0x140002700 | PCI Write | 8+data | 0 |
