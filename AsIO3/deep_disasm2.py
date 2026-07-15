"""
Deep disassembly part 2:
- The notify callback at 0x3CD0 only handles EXIT (r8==NULL clears PID)
- When r8 != NULL (creation), it jumps to 0x3D07 which is just RET
  BUT WAIT: jne 0x140003d07... that 0x3D07 is PAST the ret at 0x3D07
  Actually 0x3D07 IS the ret instruction. So if r8 != NULL, it just returns!

This means the PROCESS CREATION whitelist enrollment is NOT in this callback!
The path check must happen elsewhere. Let's look at:
1. The function at RVA 0x16C4 (called from DriverEntry)
2. IRP_MJ_CREATE dispatch (the device open handler)
3. Search for references to the path string at RVA 0x7D20
"""
import pefile
import capstone
import struct
import json

DRIVER_PATH = r"C:\Users\researcher\OneDrive\Desktop\report\AsIO3\Asusgio3.sys"

pe = pefile.PE(DRIVER_PATH)
IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def rva_to_offset(rva):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData
    return None

def disasm_range(rva, size, label=""):
    offset = rva_to_offset(rva)
    if offset is None:
        print(f"  [ERROR] Cannot resolve RVA 0x{rva:X}")
        return []
    raw = pe.__data__[offset:offset+size]
    instructions = list(md.disasm(raw, IMAGE_BASE + rva))
    print(f"\n{'='*80}")
    print(f"  {label} (RVA 0x{rva:X}, VA 0x{IMAGE_BASE+rva:X})")
    print(f"{'='*80}")
    for ins in instructions:
        print(f"  0x{ins.address:X}:  {ins.mnemonic:<10} {ins.op_str}")
    return instructions

# ============================================================
# KEY INSIGHT: The static array at .data+0x00 is NOT PIDs!
# Values like 0xC0010015 are MSR addresses (AMD MSRs)
# The first few (0x35, 0xCE, 0x150...) are Intel MSR addresses
# This is the MSR WHITELIST, not PID whitelist!
# ============================================================
print("="*80)
print("  CRITICAL FINDING: .data+0x00 is MSR WHITELIST, NOT PID WHITELIST!")
print("="*80)
print("""
  The 29 entries are allowed MSR addresses:
  0x35=CORE_THREAD_COUNT, 0xCE=MSR_PLATFORM_INFO, 0x150=?, 0x194=CLOCK_MOD
  0x198=PERF_STATUS, 0x1A2=TEMPERATURE_TARGET, 0x1B1=?, 0x1A0=MISC_ENABLE
  0x606=MSR_RAPL_POWER_UNIT, 0x610-0x651=RAPL domains, 0x770-0x774=HWP
  0xC001xxxx=AMD MSRs (HWCR, P-state, etc.)

  The REAL PID whitelist is the QWORD array at .data+0x3C0!
  But those values look weird too - they appear to be PAIRS packed into QWORDs.
""")

# Let's re-examine the QWORD array
print("\n  Re-examining QWORD array at .data+0x3C0:")
print("  These might be {high_DWORD, low_DWORD} = {something, something}")
data_off = None
for s in pe.sections:
    if b'.data' in s.Name:
        data_off = s.PointerToRawData
        break

if data_off:
    for i in range(64):
        val = struct.unpack_from('<Q', pe.__data__, data_off + 0x3C0 + i*8)[0]
        if val != 0:
            hi = (val >> 32) & 0xFFFFFFFF
            lo = val & 0xFFFFFFFF
            print(f"    [{i:2d}] hi=0x{hi:08X} lo=0x{lo:08X}")

# ============================================================
# Look at function 0x16C4 (called from DriverEntry init)
# This likely sets up the dispatch table
# ============================================================
print("\n")
disasm_range(0x16C4, 1024, "Init Function called from DriverEntry (RVA 0x16C4)")

# ============================================================
# The process notify callback does JNE to 0x3D07 (ret) when r8!=NULL
# So it ONLY processes exits. Where does creation go?
# Let's look for another callback or the actual enrollment logic
# ============================================================

# Search for references to string "AsusCertService" (RVA 0x7D20)
# by scanning for LEA instructions with RIP-relative addressing
print("\n\n" + "="*80)
print("  SEARCHING FOR REFERENCES TO PATH STRING (RVA 0x7D20, VA 0x140007D20)")
print("="*80)

# Scan all code sections for instructions that reference near 0x7D20
target_va = IMAGE_BASE + 0x7D20

for section in pe.sections:
    if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
        sec_name = section.Name.decode().rstrip('\x00')
        sec_rva = section.VirtualAddress
        sec_off = section.PointerToRawData
        sec_size = min(section.Misc_VirtualSize, section.SizeOfRawData)

        raw = pe.__data__[sec_off:sec_off+sec_size]
        instructions = list(md.disasm(raw, IMAGE_BASE + sec_rva))

        for ins in instructions:
            if 'rip' in ins.op_str and ins.mnemonic == 'lea':
                # Calculate RIP-relative target
                # Need to find the displacement from the instruction bytes
                ins_offset = ins.address - (IMAGE_BASE + sec_rva) + sec_off
                ins_bytes = pe.__data__[ins_offset:ins_offset+ins.size]

                # For LEA with RIP-relative, displacement is last 4 bytes
                if ins.size >= 7:  # REX + opcode + modrm + 4-byte disp
                    disp = struct.unpack_from('<i', ins_bytes, ins.size - 4)[0]
                    resolved = ins.address + ins.size + disp

                    # Check if it points to our target string area (within 0x100 bytes)
                    if abs(resolved - target_va) < 0x100:
                        print(f"  FOUND: 0x{ins.address:X} ({sec_name}): {ins.mnemonic} {ins.op_str}")
                        print(f"         -> resolves to VA 0x{resolved:X} (RVA 0x{resolved-IMAGE_BASE:X})")
                        print(f"         Distance from target: {resolved - target_va} bytes")
                        # Disassemble context around this
                        ctx_rva = (ins.address - IMAGE_BASE) - 0x40
                        disasm_range(ctx_rva, 0x200, f"Context around string reference at 0x{ins.address:X}")

# ============================================================
# Also look at all functions that call PsGetProcessImageFileName
# ============================================================
print("\n\n" + "="*80)
print("  SEARCHING FOR PsGetProcessImageFileName CALLS")
print("="*80)

# Find IAT entry for PsGetProcessImageFileName
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    if b'ntoskrnl' in entry.dll.lower():
        for imp in entry.imports:
            if imp.name and b'PsGetProcessImageFileName' in imp.name:
                print(f"  Import: {imp.name.decode()} at IAT VA 0x{imp.address:X}")
                # Now find CALL [rip+X] that targets this IAT entry
                iat_va = imp.address

                for section in pe.sections:
                    if section.Characteristics & 0x20000000:
                        sec_rva = section.VirtualAddress
                        sec_off = section.PointerToRawData
                        sec_size = min(section.Misc_VirtualSize, section.SizeOfRawData)
                        raw = pe.__data__[sec_off:sec_off+sec_size]
                        instrs = list(md.disasm(raw, IMAGE_BASE + sec_rva))
                        for ins2 in instrs:
                            if ins2.mnemonic == 'call' and 'rip' in ins2.op_str:
                                ins_off2 = ins2.address - (IMAGE_BASE + sec_rva) + sec_off
                                ins_bytes2 = pe.__data__[ins_off2:ins_off2+ins2.size]
                                if ins2.size >= 6:
                                    disp2 = struct.unpack_from('<i', ins_bytes2, ins2.size - 4)[0]
                                    resolved2 = ins2.address + ins2.size + disp2
                                    if resolved2 == iat_va:
                                        rva2 = ins2.address - IMAGE_BASE
                                        print(f"  CALL PsGetProcessImageFileName at VA 0x{ins2.address:X} (RVA 0x{rva2:X})")

# ============================================================
# Look at 0x7323 - the function called from within the notify callback
# (might be ExAcquireFastMutex or similar sync)
# ============================================================
print("\n")
disasm_range(0x7323, 64, "Function called from notify callback (0x7323)")

print("\n\nDONE")
