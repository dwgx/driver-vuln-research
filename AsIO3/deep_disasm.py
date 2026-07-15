"""
Deep disassembly of Asusgio3.sys critical functions:
1. Process notify callback at RVA 0x3CD0
2. IRP_MJ_CREATE handler
3. PID whitelist check at RVA 0x14BC
"""
import pefile
import capstone
import struct
import json

DRIVER_PATH = r"C:\Users\researcher\OneDrive\Desktop\report\AsIO3\Asusgio3.sys"

pe = pefile.PE(DRIVER_PATH)
IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase  # 0x140000000 typically

# Get raw data
data = pe.get_memory_mapped_image()

# Setup disassembler
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def rva_to_offset(rva):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData
    return None

def disasm_at_rva(rva, size=512, label=""):
    offset = rva_to_offset(rva)
    if offset is None:
        print(f"  [ERROR] Cannot resolve RVA 0x{rva:X}")
        return []
    raw = pe.__data__[offset:offset+size]
    instructions = list(md.disasm(raw, IMAGE_BASE + rva))
    print(f"\n{'='*80}")
    print(f"  DISASSEMBLY: {label} (RVA 0x{rva:X}, VA 0x{IMAGE_BASE+rva:X})")
    print(f"{'='*80}")
    results = []
    for ins in instructions:
        line = f"  0x{ins.address:X}:  {ins.mnemonic:<10} {ins.op_str}"
        print(line)
        results.append({"addr": ins.address, "mnemonic": ins.mnemonic, "op_str": ins.op_str})
        # Stop at ret or int3 after reasonable amount
        if ins.mnemonic == 'ret' and len(results) > 10:
            break
        if ins.mnemonic == 'int3' and len(results) > 5:
            break
    return results

def find_strings_near_rva(rva, search_range=0x200):
    """Find unicode strings referenced near an RVA"""
    offset = rva_to_offset(rva)
    if offset is None:
        return []
    strings_found = []
    raw = pe.__data__[offset:offset+search_range]
    # Look for LEA instructions that reference string data
    instructions = list(md.disasm(raw, IMAGE_BASE + rva))
    for ins in instructions:
        if ins.mnemonic == 'lea' and 'rip' in ins.op_str:
            # Calculate target address
            # The displacement is in the instruction encoding
            try:
                # Parse RIP-relative address
                if '+' in ins.op_str and 'rip' in ins.op_str:
                    # e.g., "rcx, [rip + 0x1234]"
                    disp_str = ins.op_str.split('rip')[1].strip().rstrip(']')
                    if '+' in disp_str:
                        disp = int(disp_str.replace('+','').strip(), 16)
                    elif '-' in disp_str:
                        disp = -int(disp_str.replace('-','').strip(), 16)
                    else:
                        continue
                    target_va = ins.address + ins.size + disp
                    target_rva = target_va - IMAGE_BASE
                    target_off = rva_to_offset(target_rva)
                    if target_off and target_off < len(pe.__data__) - 100:
                        # Try to read as unicode string
                        raw_str = pe.__data__[target_off:target_off+200]
                        try:
                            ustr = raw_str.decode('utf-16-le').split('\x00')[0]
                            if len(ustr) > 3 and ustr.isprintable():
                                strings_found.append({
                                    "at_va": ins.address,
                                    "target_rva": target_rva,
                                    "string": ustr
                                })
                        except:
                            pass
            except:
                pass
    return strings_found

print("="*80)
print("  ASUSGIO3.SYS DEEP DISASSEMBLY ANALYSIS")
print("="*80)
print(f"\n  Image Base: 0x{IMAGE_BASE:X}")
print(f"  File Size: {len(pe.__data__)} bytes")

# Print sections
print("\n  Sections:")
for s in pe.sections:
    name = s.Name.decode().rstrip('\x00')
    print(f"    {name:8s} VA=0x{s.VirtualAddress:X} Size=0x{s.Misc_VirtualSize:X} Raw=0x{s.PointerToRawData:X}")

# ============================================================
# 1. PROCESS NOTIFY CALLBACK at RVA 0x3CD0
# ============================================================
print("\n\n" + "#"*80)
print("# SECTION 1: PROCESS NOTIFY CALLBACK (RVA 0x3CD0)")
print("#"*80)
print("""
This is registered via PsSetCreateProcessNotifyRoutineEx.
Parameters: (PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
  - RCX = PEPROCESS
  - RDX = ProcessId (HANDLE, but really a PID)
  - R8 = PPS_CREATE_NOTIFY_INFO (NULL if process is exiting)
""")

# Disassemble a large chunk to get the full function
notify_instrs = disasm_at_rva(0x3CD0, 1024, "ProcessNotifyCallback")

# Let's also look at the broader function - it might be longer
print("\n\n  --- Continuing disassembly past first ret ---")
disasm_at_rva(0x3CD0, 2048, "ProcessNotifyCallback (extended)")

# ============================================================
# 2. Find the string comparison logic
# ============================================================
print("\n\n" + "#"*80)
print("# SECTION 2: STRING REFERENCES IN NOTIFY CALLBACK")
print("#"*80)

strings = find_strings_near_rva(0x3CD0, 0x800)
print(f"\n  Found {len(strings)} string references:")
for s in strings:
    print(f"    At VA 0x{s['at_va']:X} -> RVA 0x{s['target_rva']:X}: \"{s['string']}\"")

# Also check the known string location
print("\n  --- Known string at file offset 0x7120 ---")
str_off = 0x7120
raw_str = pe.__data__[str_off:str_off+200]
try:
    ustr = raw_str.decode('utf-16-le').split('\x00')[0]
    print(f"    String: \"{ustr}\"")
    print(f"    Length: {len(ustr)} chars")
except:
    print("    [Could not decode as UTF-16LE]")

# Find RVA of this string
for section in pe.sections:
    if section.PointerToRawData <= str_off < section.PointerToRawData + section.SizeOfRawData:
        str_rva = str_off - section.PointerToRawData + section.VirtualAddress
        print(f"    RVA: 0x{str_rva:X}")
        print(f"    VA:  0x{IMAGE_BASE + str_rva:X}")
        break

# ============================================================
# 3. PID WHITELIST CHECK at RVA 0x14BC
# ============================================================
print("\n\n" + "#"*80)
print("# SECTION 3: PID WHITELIST CHECK (RVA 0x14BC)")
print("#"*80)
print("""
Called from IOCTL dispatch to validate caller PID.
Expected: takes PID, returns 0=allowed or 1=denied
""")
disasm_at_rva(0x14BC, 512, "PID Whitelist Check")

# ============================================================
# 4. IRP_MJ_CREATE handler
# ============================================================
print("\n\n" + "#"*80)
print("# SECTION 4: IRP_MJ_CREATE HANDLER")
print("#"*80)
print("""
Need to find the MajorFunction[IRP_MJ_CREATE] handler.
Looking at DriverEntry to find where dispatch table is set up.
""")

# Find DriverEntry - it's the entry point
entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print(f"\n  DriverEntry RVA: 0x{entry_rva:X}")
disasm_at_rva(entry_rva, 512, "DriverEntry")

# ============================================================
# 5. Look for the SD / security setup
# ============================================================
print("\n\n" + "#"*80)
print("# SECTION 5: SECURITY DESCRIPTOR SETUP (RVA 0xB410)")
print("#"*80)
disasm_at_rva(0xB410, 512, "SecurityDescriptor Setup")

# ============================================================
# 6. Examine .data section for whitelist arrays
# ============================================================
print("\n\n" + "#"*80)
print("# SECTION 6: .DATA SECTION WHITELIST STRUCTURES")
print("#"*80)

data_section = None
for s in pe.sections:
    if b'.data' in s.Name:
        data_section = s
        break

if data_section:
    data_rva = data_section.VirtualAddress
    data_off = data_section.PointerToRawData
    data_size = data_section.Misc_VirtualSize
    print(f"\n  .data section: RVA=0x{data_rva:X}, offset=0x{data_off:X}, size=0x{data_size:X}")

    # Static PID array at .data+0x00 (29 DWORDs)
    print(f"\n  Static PID array (.data+0x00, 29 DWORDs):")
    for i in range(29):
        val = struct.unpack_from('<I', pe.__data__, data_off + i*4)[0]
        if val != 0:
            print(f"    [{i:2d}] = 0x{val:08X} ({val})")

    # QWORD array at .data+0x3C0 (64 entries)
    print(f"\n  QWORD PID array (.data+0x3C0, 64 entries):")
    for i in range(64):
        val = struct.unpack_from('<Q', pe.__data__, data_off + 0x3C0 + i*8)[0]
        if val != 0:
            print(f"    [{i:2d}] = 0x{val:016X} ({val})")

    # Dynamic pointer at .data+0x5D0
    print(f"\n  Dynamic whitelist pointer (.data+0x5D0):")
    val = struct.unpack_from('<Q', pe.__data__, data_off + 0x5D0)[0]
    print(f"    Pointer: 0x{val:016X}")
    val2 = struct.unpack_from('<Q', pe.__data__, data_off + 0x5D8)[0]
    print(f"    Pointer+8: 0x{val2:016X}")

print("\n\n  ANALYSIS COMPLETE")
