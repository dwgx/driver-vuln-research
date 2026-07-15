# AsIO3 Named Pipe Protocol — Full Reverse Engineering Report

## Executive Summary

AsusCertService v1.3.2 (`\\.\pipe\asuscert`) implements a **PID registration** protocol,
NOT a proxy for driver IOCTLs. The pipe accepts a 4-byte PID, verifies the sender's
code signature (WinVerifyTrust), and if the sender is an ASUS-signed binary, registers
the PID in the driver's internal whitelist via IOCTL `0xA040A490`.

**Bottom line**: The pipe alone cannot be used to read physical memory because:
1. The driver checks the PID whitelist at IRP_MJ_CREATE time (device open)
2. Only PIDs of ASUS-signed executables get registered via the pipe
3. The pipe ALWAYS returns "OK!" regardless of whether registration succeeded
4. Even SYSTEM processes are blocked unless their PID is in the whitelist
5. Only AsusCertService.exe itself bypasses the check (driver recognizes its path)

**Exploitation path**: Patch AsusCertService.exe at RVA 0x135B6 to skip verification,
then any process's PID will be registered, allowing it to open the device and use all
IOCTLs including physical memory map (0xA040200C).

---

## Pipe Configuration

| Property | Value |
|----------|-------|
| Pipe Name | `\\.\pipe\asuscert` |
| Mode | `PIPE_TYPE_MESSAGE \| PIPE_READMODE_MESSAGE` |
| Max Instances | 1 |
| In Buffer | 128 bytes |
| Out Buffer | 64 bytes |
| Timeout | 5000ms |
| Open Mode | `PIPE_ACCESS_DUPLEX \| FILE_FLAG_OVERLAPPED \| WRITE_DAC` |
| Security | Accessible from non-elevated processes (confirmed) |

---

## Protocol Flow

```
Client                              AsusCertService v1.3.2
  |                                        |
  |--- CreateFile(\\.\pipe\asuscert) ----->|  (ConnectNamedPipe accepts)
  |                                        |
  |--- WriteFile(4-byte PID) ------------>|  (reads PID)
  |                                        |
  |                                        |--- OpenProcess(PID, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ)
  |                                        |--- K32GetModuleFileNameExW(hProcess)
  |                                        |--- PathFindFileNameW(path)
  |                                        |--- WinVerifyTrust(exe_path)  [signature check]
  |                                        |--- Compare exe name against whitelist
  |                                        |
  |                                        |  IF verified:
  |                                        |--- CreateFileA("\\.\Asusgio3") [if not cached]
  |                                        |--- DeviceIoControl(0xA040A490, &PID, 4)
  |                                        |
  |<-- ReadFile("OK!" as UTF-16LE) -------|  (ALWAYS sent, even on failure)
  |                                        |
  |--- CloseHandle ---------------------->|  (DisconnectNamedPipe)
```

### Key Points

1. **Message format**: Client sends exactly 4 bytes (DWORD, little-endian) = its own PID
2. **Response**: Always "OK!" (UTF-16LE, 8 bytes: `4f 00 4b 00 21 00 00 00`) regardless of success/failure
3. **No error feedback**: The pipe response does not indicate whether registration succeeded
4. **Single IOCTL**: Only `0xA040A490` is ever called — no physical memory operations via pipe

---

## IOCTL 0xA040A490 — PID Registration

```
CTL_CODE(0xA040, 0x924, METHOD_BUFFERED, FILE_WRITE_ACCESS)

Input:  4 bytes — DWORD value (stored in driver's PID table)
Output: None (0 bytes)
```

### Driver Behavior (Asusgio3.sys)

The driver maintains a table of 64 QWORD entries at `.data+0x93C0`:
- IOCTL 0xA040A490 stores the input value in the first empty slot
- Before processing physical memory IOCTLs (0xA040200C map, 0xA0402010 unmap), 
  the driver calls an access check function at offset 0x340C
- This function calls `PsGetCurrentProcessId()` and scans the table for a match
- If found: returns STATUS_SUCCESS (IOCTL proceeds)
- If not found: returns STATUS_UNSUCCESSFUL (IOCTL denied)

---

## Verification Logic (AsusCertService)

### Process Identification (RVA 0x134C0)

1. Receives PID from pipe message
2. `OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, PID)` → gets handle
3. `K32GetModuleFileNameExW(hProcess, NULL, buf, 0x104)` → gets full exe path
4. `PathFindFileNameW(path)` → extracts filename only

### Certificate Verification (RVA 0x10090)

Uses WinVerifyTrust with `WINTRUST_ACTION_GENERIC_VERIFY_V2`:
- GUID: `{AAC56B-11D0CD44-C000C28C-EE95C24F}`
- Checks for Authenticode signature on the client executable
- Known error codes handled: `0x800B0100`, `0x80096010`, `0x800B0001`

### Executable Whitelist (RVA 0x13790)

- Compares filename against a runtime-populated list of 14 entries (0x50 bytes each)
- List is at RVA `0x6FD70` — populated at service startup from configuration
- The whitelist entries are zero-initialized in the binary (populated dynamically)
- Likely contains: `ArmouryCrate.exe`, `AsusOptimization.exe`, etc.

---

## Device Security Architecture

### Device Object

| Property | Value |
|----------|-------|
| Device Path | `\Device\Asusgio3` |
| Symlink | `\DosDevices\Asusgio3` |
| Device Type | `0xA040` |
| Characteristics | `FILE_DEVICE_SECURE_OPEN (0x100)` |
| Flags | `DO_DIRECT_IO` |
| DACL | **SYSTEM-only** (programmatically set via `RtlSetDaclSecurityDescriptor` + `ZwSetSecurityObject`) |

### Access Control Layers

```
Layer 1: PID Whitelist (IRP_MJ_CREATE / CreateFile)
  → Driver checks PsGetCurrentProcessId() against the PID table
  → If PID not found: STATUS_ACCESS_DENIED (Win32 error 5)
  → EXCEPTION: if caller is AsusCertService.exe (path check), bypass allowed
  → This is the FIRST check — even SYSTEM is blocked without PID registration

Layer 2: PID Whitelist (DeviceIoControl — sensitive IOCTLs)
  → Physical memory IOCTLs (0xA040200C, 0xA0402010) additionally re-check PID
  → Port I/O and MSR IOCTLs also validate via access check at 0x143C

Layer 3: Address Range Check (g_goodRanges)
  → Physical memory map IOCTL additionally checks against allowed address ranges
  → Only specific physical ranges are mappable (to prevent arbitrary kernel read)
```

### IRP_MJ_CREATE Handler (RVA 0x2777 in driver)

```c
// Pseudocode of the driver's CreateFile handler
NTSTATUS IRP_MJ_CREATE_handler(DEVICE_OBJECT *dev, IRP *irp) {
    // Check 1: Is the caller AsusCertService.exe?
    if (is_asuscertservice_process()) {  // 0x3138
        register_process_info();          // 0x2D88
        return STATUS_SUCCESS;
    }
    
    // Check 2: Is caller's PID in the whitelist?
    NTSTATUS status = check_pid_whitelist();  // 0x340C
    if (status < 0) {
        return STATUS_ACCESS_DENIED;  // 0xC0000022
    }
    return STATUS_SUCCESS;
}
```

---

## Tested Behaviors

### From Non-Elevated Process
- Pipe open: **SUCCESS** (pipe security allows everyone)
- Pipe write (PID): **SUCCESS** (4 bytes written)
- Pipe read response: **"OK!"** received (but PID NOT registered — sig check failed)
- Device open: **ERROR_ACCESS_DENIED (5)** — PID not in driver whitelist

### From Elevated (Admin) Process
- Same pipe behavior (OK but not registered)
- Device open: **ERROR_ACCESS_DENIED (5)** — PID not in whitelist
- With SeDebugPrivilege: still **ERROR_ACCESS_DENIED**

### From SYSTEM (Scheduled Task)
- Same pipe behavior (OK but not registered)  
- Device open: **ERROR_ACCESS_DENIED (5)** — even SYSTEM blocked without PID registration
- This confirms the driver does NOT use a DACL — it uses PID-based access control

### DuplicateHandle from Service
- `OpenProcess(AsusCertService_PID, PROCESS_DUP_HANDLE)`: **ERROR_ACCESS_DENIED (5)**
- Service process appears to be protected against handle operations

---

## All Driver IOCTLs (Asusgio3.sys)

| IOCTL Code | Function | Purpose |
|------------|----------|---------|
| 0xA0400F58 | 0x3D6 | Unknown (EC?) |
| 0xA0400F5C | 0x3D7 | Unknown |
| 0xA0400F60 | 0x3D8 | Unknown |
| 0xA0400F64 | 0x3D9 | Unknown |
| 0xA0400F68 | 0x3DA | Unknown |
| 0xA0400F6C | 0x3DB | Unknown |
| 0xA0400F70 | 0x3DC | Unknown |
| 0xA0400F74 | 0x3DD | Unknown |
| 0xA0400F78 | 0x3DE | Unknown |
| 0xA0400F7C | 0x3DF | Unknown |
| 0xA0400F80 | 0x3E0 | Unknown |
| 0xA0400F84 | 0x3E1 | Unknown |
| 0xA0400F88 | 0x3E2 | Unknown |
| 0xA0400F8C | 0x3E3 | Unknown |
| 0xA0400F90 | 0x3E4 | Unknown |
| 0xA0400F94 | 0x3E5 | Unknown |
| 0xA0402000 | 0x800 | Read I/O Port (IN instruction) |
| 0xA0402004 | 0x801 | Write I/O Port (OUT instruction) |
| 0xA040200C | 0x803 | **Map Physical Memory** |
| 0xA0402010 | 0x804 | **Unmap Physical Memory** |
| 0xA0402014 | 0x805 | Unknown |
| 0xA0402018 | 0x806 | Unknown |
| 0xA040244C | 0x913 | Unknown |
| 0xA0402450 | 0x914 | Unknown |
| 0xA0406400 | 0x900 | PCI Config (related) |
| 0xA0406404 | 0x901 | PCI Config (related) |
| 0xA0406408 | 0x902 | PCI Config (related) |
| 0xA040640C | 0x903 | PCI Config Read |
| 0xA0406458 | 0x916 | PCI Config (extended) |
| 0xA040A440 | 0x910 | MSR-related |
| 0xA040A444 | 0x911 | MSR-related |
| 0xA040A448 | 0x912 | MSR-related |
| 0xA040A45C | 0x917 | Unknown |
| 0xA040A480 | 0x920 | Unknown |
| 0xA040A488 | 0x922 | Unknown |
| 0xA040A48C | 0x923 | Process handle cleanup |
| 0xA040A490 | 0x924 | **Register PID in whitelist** |
| 0xA040A540 | 0x950 | Unknown |
| 0xA040A544 | 0x951 | Unknown |
| 0xA040A548 | 0x952 | Unknown |
| 0xA040A54C | 0x953 | Unknown |
| 0xA040B941 | — | Seen in code (context unclear) |

---

## Why the Pipe Cannot Be Used for Physical Memory Access (Without Patching)

1. **Signature verification blocks registration**: WinVerifyTrust must pass for ASUS cert
2. **"OK!" is always returned**: no way to know if registration succeeded
3. **No IOCTL proxy**: the service does NOT forward arbitrary IOCTLs from the pipe
4. **PID check at device open**: even if PID were registered, it must be the SAME process
5. **Single IOCTL only**: only 0xA040A490 (register PID) is called — never map/unmap
6. **Service process is protected**: can't DuplicateHandle or OpenProcess against it

---

## Viable Alternative Approaches

### 1. Patch AsusCertService.exe (RECOMMENDED — simplest)

Patch 6 bytes to skip the WinVerifyTrust check:
- **File offset**: `0x129B6` (RVA `0x135B6`)
- **Original**: `0F 84 BD 04 00 00` (JE +0x4BD — jump to failure if cert invalid)
- **Patched**: `90 90 90 90 90 90` (NOP x6 — always fall through to success path)

This alone is sufficient if the process whitelist is empty or matches.
If the whitelist also blocks, additionally NOP out the failure at file offset
`0x137F5` (RVA 0x137F5, the `jmp` to failure after all comparisons exhaust).

After patching:
1. Stop the service: `net stop AsusCertService`
2. Copy and patch the binary (backup the original!)
3. Start the service: `net start AsusCertService`
4. Connect to pipe, send your PID — it WILL be registered
5. Open `\\.\Asusgio3` from the registered process — SUCCESS
6. Call DeviceIoControl with IOCTL 0xA040200C for physical memory

### 2. DLL injection into AsusCertService.exe

Since AsusCertService already has the device open (it bypasses PID check):
- Inject a DLL that calls DeviceIoControl on the existing handle
- The handle is stored at global RVA 0x6FC3F (approximately)
- Injection requires admin + SeDebugPrivilege, but the service may resist

### 3. Hijack an ASUS-signed process

Find a signed ASUS exe, launch it suspended, inject payload:
- `ArmouryCrate.exe`, `AsusOptimization.exe`, or similar
- These pass the WinVerifyTrust check
- Their PIDs get registered
- Then they can open the device

### 4. Direct driver IOCTL from AsusCertService's context

Since AsusCertService runs as SYSTEM and has the device open:
- Write a small named pipe server that AsusCertService connects to (unlikely)
- Or modify the service binary to expose a second pipe with full IOCTL proxy

### 5. Alternative drivers (bypass AsIO3 entirely)

Use a different vulnerable driver that has no such restrictions:
- **SIVX64.sys** — simpler access model, no PID whitelist
- **ASMMAP64.sys** — direct memory mapping without registration
- **ASTRA64.sys** — physical memory access
These are already available in `drivers/Vulnerable-Monitors/`

---

## Relevant Addresses (AsusCertService.exe v1.3.2)

| Item | RVA |
|------|-----|
| Pipe string (`\\.\pipe\asuscert`) | 0x62A08 |
| Device string (`\\.\Asusgio3`) | 0x61130 |
| CreateNamedPipeW call | 0x12BF0 |
| Pipe server loop | 0x12E50 |
| ReadFile (from pipe) | 0x13129 |
| WriteFile (to pipe) | 0x1309E |
| Handler function | 0x134C0 |
| OpenProcess call | 0x134FD |
| K32GetModuleFileNameExW | 0x1351A |
| WinVerifyTrust check | 0x135AF (call to 0x10090) |
| Whitelist comparison | 0x13790 |
| CreateFileA (device) | 0x13906 |
| DeviceIoControl (register PID) | 0x139C6 |
| Response buffer "OK!" | 0x6FC50 |
| Pipe handle global | 0x74B28 |
| Pipe read buffer / PID storage | 0x74B30 |
| State variable | 0x74B38 |

---

## Relevant Addresses (Asusgio3.sys)

| Item | RVA |
|------|-----|
| DriverEntry | 0xD000 |
| Main setup function | 0x16C4 |
| IRP_MJ_CREATE dispatch | 0x19A0 (set at DriverObj+0x70) |
| IOCTL dispatch | 0x1A83+ |
| PID registration handler (0xA040A490) | 0x3DE0 |
| PID table (64 QWORD entries) | 0x93C0 |
| PID access check function | 0x340C |
| Physical memory map handler | 0x345C+ |
| Device name (`\Device\Asusgio3`) | 0x7B40 |
| Symlink (`\DosDevices\Asusgio3`) | 0x7B70 |
