"""
Handle enumeration v2 - uses SystemExtendedHandleInformation for 64-bit PIDs.
Must run as Administrator.
"""
import ctypes
import ctypes.wintypes as wintypes
from ctypes import Structure, POINTER, sizeof, byref, windll, cast, c_void_p, c_ulong, c_ulonglong
import struct
import sys
import os
import json

ntdll = windll.ntdll
kernel32 = windll.kernel32

STATUS_INFO_LENGTH_MISMATCH = 0xC0000004 & 0xFFFFFFFF
SystemExtendedHandleInformation = 64
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
DUPLICATE_SAME_ACCESS = 0x00000002
ObjectNameInformation = 1

def get_process_name(pid):
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return "<unknown>"
    try:
        buf = (ctypes.c_wchar * 520)()
        size = wintypes.DWORD(520)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, byref(size)):
            return buf.value
        return "<unknown>"
    finally:
        kernel32.CloseHandle(h)

def enumerate_handles():
    results = []

    # Use SystemExtendedHandleInformation (64) for proper 64-bit support
    buf_size = 0x1000000  # 16MB
    while True:
        buf = ctypes.create_string_buffer(buf_size)
        ret_len = ctypes.c_ulong(0)
        status = ntdll.NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            buf, buf_size, byref(ret_len)
        )
        status_unsigned = status & 0xFFFFFFFF
        if status_unsigned == STATUS_INFO_LENGTH_MISMATCH:
            buf_size *= 2
            if buf_size > 0x40000000:
                print("ERROR: Buffer too large")
                return results
            continue
        elif status < 0:
            print(f"ERROR: NtQuerySystemInformation failed: 0x{status_unsigned:08X}")
            return results
        break

    # SYSTEM_HANDLE_INFORMATION_EX layout:
    # +0x00: NumberOfHandles (ULONG_PTR = 8 bytes on x64)
    # +0x08: Reserved (ULONG_PTR = 8 bytes)
    # +0x10: Handles[] array
    # Each SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX:
    #   +0x00: Object (void*, 8 bytes)
    #   +0x08: UniqueProcessId (ULONG_PTR, 8 bytes)
    #   +0x10: HandleValue (ULONG_PTR, 8 bytes)
    #   +0x18: GrantedAccess (ULONG, 4 bytes)
    #   +0x1C: CreatorBackTraceIndex (USHORT, 2 bytes)
    #   +0x1E: ObjectTypeIndex (USHORT, 2 bytes)
    #   +0x20: HandleAttributes (ULONG, 4 bytes)
    #   +0x24: Reserved (ULONG, 4 bytes)
    # Total entry size: 0x28 (40 bytes)

    raw = buf.raw
    num_handles = struct.unpack_from('<Q', raw, 0)[0]
    print(f"Total system handles: {num_handles}")

    entry_size = 0x28  # 40 bytes per entry on x64
    entries_offset = 0x10  # Skip NumberOfHandles + Reserved

    # Find ASUS processes
    asus_pids = set()
    target_pids = set()

    # Collect all unique PIDs first
    all_pids = set()
    for i in range(min(num_handles, 500000)):
        offset = entries_offset + i * entry_size
        if offset + entry_size > len(raw):
            break
        pid = struct.unpack_from('<Q', raw, offset + 8)[0]
        all_pids.add(pid)

    print(f"Unique PIDs: {len(all_pids)}")

    # Find ASUS-related PIDs
    for pid in all_pids:
        if pid == 0 or pid == 4 or pid > 100000:
            continue
        try:
            name = get_process_name(pid)
            name_lower = name.lower()
            if any(x in name_lower for x in ['asus', 'armoury', 'certservice', 'aura', 'myasus']):
                asus_pids.add(pid)
                target_pids.add(pid)
                print(f"  ASUS process: PID {pid} = {os.path.basename(name)}")
        except:
            pass

    # Always include 3760
    target_pids.add(3760)

    print(f"\nScanning handles for target PIDs: {target_pids}")

    # Scan all handles belonging to target PIDs
    for i in range(min(num_handles, 500000)):
        offset = entries_offset + i * entry_size
        if offset + entry_size > len(raw):
            break

        pid = struct.unpack_from('<Q', raw, offset + 8)[0]
        if pid not in target_pids:
            continue

        handle_val = struct.unpack_from('<Q', raw, offset + 0x10)[0]
        access = struct.unpack_from('<I', raw, offset + 0x18)[0]
        type_idx = struct.unpack_from('<H', raw, offset + 0x1E)[0]

        # Try to duplicate and query name
        h_proc = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if not h_proc:
            continue

        dup_handle = wintypes.HANDLE(0)
        status2 = ntdll.NtDuplicateObject(
            h_proc, handle_val,
            kernel32.GetCurrentProcess(),
            byref(dup_handle), 0, 0, DUPLICATE_SAME_ACCESS
        )

        if status2 < 0:
            kernel32.CloseHandle(h_proc)
            continue

        # Query object name
        name_buf = ctypes.create_string_buffer(2048)
        ret_len2 = ctypes.c_ulong(0)
        status3 = ntdll.NtQueryObject(
            dup_handle, ObjectNameInformation,
            name_buf, 2048, byref(ret_len2)
        )

        obj_name = ""
        if status3 >= 0:
            name_len = struct.unpack_from('<H', name_buf.raw, 0)[0]
            if name_len > 0 and name_len < 1024:
                try:
                    obj_name = name_buf.raw[8:8+name_len].decode('utf-16-le')
                except:
                    pass

        kernel32.CloseHandle(dup_handle)
        kernel32.CloseHandle(h_proc)

        if 'asusgio' in obj_name.lower() or 'asio3' in obj_name.lower():
            proc_name = get_process_name(pid)
            result = {
                "pid": pid,
                "process": proc_name,
                "handle": handle_val,
                "access": access,
                "object_name": obj_name,
                "type_index": type_idx
            }
            results.append(result)
            print(f"  *** FOUND: PID {pid} Handle 0x{handle_val:X} -> {obj_name}")
            print(f"      Access: 0x{access:08X}, Type: {type_idx}")

    return results

def test_direct_open():
    """Test if we can directly open the device"""
    kernel32.CreateFileW.restype = wintypes.HANDLE
    h = kernel32.CreateFileW(
        r"\\.\Asusgio3",
        0xC0000000,
        3, None, 3, 0, None
    )
    err = kernel32.GetLastError()
    if h and h != wintypes.HANDLE(-1).value and h != 0xFFFFFFFFFFFFFFFF:
        print(f"  CreateFileW SUCCEEDED! Handle = 0x{h:X}")
        kernel32.CloseHandle(h)
        return True
    else:
        print(f"  CreateFileW failed: error {err} ({'ACCESS_DENIED' if err == 5 else 'FILE_NOT_FOUND' if err == 2 else f'code {err}'})")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("  ASUSGIO3 HANDLE ENUMERATION v2")
    print("=" * 60)
    print(f"  Our PID: {os.getpid()}")

    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    print(f"  Admin: {'YES' if is_admin else 'NO'}")

    if not is_admin:
        print("\n  WARNING: Not running as admin. Handle enum may be incomplete.")
        print("  Recommend running: python handle_enum2.py (from admin prompt)")

    print()
    results = enumerate_handles()

    print(f"\n{'=' * 60}")
    print(f"  RESULTS: {len(results)} Asusgio3 handle(s) found")
    print(f"{'=' * 60}")

    for r in results:
        print(f"  PID {r['pid']} ({os.path.basename(r['process'])})")
        print(f"    Handle: 0x{r['handle']:X}")
        print(f"    Access: 0x{r['access']:08X}")
        print(f"    Name:   {r['object_name']}")

    print(f"\n  Direct open test:")
    test_direct_open()

    # Save results
    output_path = r"C:\Users\researcher\OneDrive\Desktop\report\AsIO3\handle_results.json"
    with open(output_path, 'w') as f:
        json.dump({"results": results, "count": len(results)}, f, indent=2, default=str)
    print(f"\n  Saved to: {output_path}")
