"""
Deep analysis part 3: Focus on the IRP_MJ_CREATE handler (RVA 0x340C)
and the path validation function at RVA 0x3100 (the big function).

KEY FINDINGS SO FAR:
1. The notify callback at 0x3CD0 ONLY removes PIDs on exit
2. The REAL enrollment happens in the function at ~0x3100
3. Function at 0x340C is the IRP_MJ_CREATE PID check:
   - Calls 0x197C (ZwQueryInformationProcess for image path)
   - Iterates QWORD array at .data+0x3C0
   - Returns 0=allowed, 0xC0000001=denied
4. The function at RVA 0x3100 does:
   - Gets process image path via ZwQueryInformationProcess (0x2B=ProcessImageFileName)
   - Compares against "C:\Program Files (x86)\ASUS\AsusCertService" (RVA 0x7D20)
   - Uses RtlCompareUnicodeString
   - If match: adds PID to whitelist
   - Has a hash/signature check too (call at 0x3276 -> 0x130C)

The critical question: function at 0x130C - what does it do?
And the comparison at 0x32D0 - is it prefix match or exact?
"""
import pefile
import capstone
import struct

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

def disasm_func(rva, max_size=512, label=""):
    offset = rva_to_offset(rva)
    if offset is None:
        print(f"  [ERROR] Cannot resolve RVA 0x{rva:X}")
        return []
    raw = pe.__data__[offset:offset+max_size]
    instructions = list(md.disasm(raw, IMAGE_BASE + rva))
    print(f"\n{'='*80}")
    print(f"  {label} (RVA 0x{rva:X})")
    print(f"{'='*80}")
    for ins in instructions:
        line = f"  0x{ins.address:X}:  {ins.mnemonic:<10} {ins.op_str}"
        print(line)
        if ins.mnemonic == 'ret':
            break
        if ins.mnemonic == 'int3':
            break
    return instructions

# ============================================================
# Function 0x340C: IRP_MJ_CREATE handler's PID check
# This is what blocks CreateFileW("\\.\Asusgio3")
# ============================================================
print("="*80)
print("  IRP_MJ_CREATE PID VALIDATION (RVA 0x340C)")
print("  This function determines if CreateFileW succeeds or returns ACCESS_DENIED")
print("="*80)

disasm_func(0x340C, 256, "IRP_MJ_CREATE PID Check")

# ============================================================
# Function 0x130C: Called during enrollment - appears to be a validation
# Called at 0x3276 with lea rcx, [rsp+0x38]
# where [rsp+0x38] was previously filled with path info
# Returns bool in AL, if AL != 0 -> jump to 0x33C2 (fail)
# ============================================================
print("\n\n" + "="*80)
print("  FUNCTION 0x130C: SECONDARY VALIDATION (hash/certificate check?)")
print("  Called during enrollment. If returns non-zero, enrollment FAILS.")
print("="*80)

disasm_func(0x130C, 512, "Secondary Validation Function")

# ============================================================
# Function 0x3B00: Called at 0x326A during enrollment
# Called with: rcx=process_info_buffer, rdx=pointer to [0x38] struct
# Returns NTSTATUS in EBX
# ============================================================
print("\n\n" + "="*80)
print("  FUNCTION 0x3B00: Path comparison/matching function")
print("="*80)

disasm_func(0x3B00, 1024, "Path Comparison Function (0x3B00)")

# ============================================================
# Let's look at what's at RVA 0x7C90 - it's referenced as an
# init string by the enrollment function
# ============================================================
print("\n\n" + "="*80)
print("  STRINGS NEAR THE PATH STRING")
print("="*80)

# Check strings at known RVAs
string_rvas = [0x7C30, 0x7C60, 0x7C90, 0x7CE0, 0x7D20, 0x7D90, 0x9150]
for rva in string_rvas:
    offset = rva_to_offset(rva)
    if offset and offset < len(pe.__data__) - 200:
        raw = pe.__data__[offset:offset+200]
        try:
            ustr = raw.decode('utf-16-le').split('\x00')[0]
            if len(ustr) > 2 and all(c.isprintable() or c in '\\/.:' for c in ustr):
                print(f"  RVA 0x{rva:X}: \"{ustr}\"")
            else:
                # Try as ASCII
                raw_a = pe.__data__[offset:offset+100]
                astr = raw_a.split(b'\x00')[0].decode('ascii', errors='replace')
                if len(astr) > 2:
                    print(f"  RVA 0x{rva:X} (ascii): \"{astr}\"")
        except:
            pass

# ============================================================
# Function 0x143C: Called at 0x1B44 in the IOCTL handler
# This might be the actual PID check used for IOCTLs
# ============================================================
print("\n\n" + "="*80)
print("  FUNCTION 0x143C: IOCTL PID Validation")
print("="*80)

disasm_func(0x143C, 256, "IOCTL PID Check (0x143C)")

# ============================================================
# Look at what the "MajorFunction" dispatch table setup actually
# stores for IRP_MJ_CREATE (offset 0x70 in DRIVER_OBJECT)
# From DriverEntry init at 0x1724:
#   lea rax, [rip + 0x2d5]  -> RVA ~0x19FD? Let me calculate
#   0x140001724 + 7 + 0x2d5 = 0x1400019FC? No...
#   0x140001724 + 7 = 0x14000172B, + 0x2d5 = 0x140001A00
# So IRP_MJ_CREATE/CLOSE/CLEANUP handler is at RVA 0x1A00!
# And:
#   lea rax, [rip + 0x1560] at 0x140001749
#   0x140001749 + 7 = 0x140001750, + 0x1560 = 0x140002CB0
# IRP_MJ_DEVICE_CONTROL handler is at RVA 0x2CB0? Let me check...
# Actually: 0x140001749 + 7 + 0x1560 = 0x140001750 + 0x1560 = 0x140002CB0
# ============================================================
print("\n\n" + "="*80)
print("  DISPATCH TABLE SETUP (from init at 0x16C4)")
print("="*80)

# Calculate actual targets
# lea rax, [rip + 0x2d5] at 0x140001724 (7 bytes)
target1 = 0x140001724 + 7 + 0x2d5
print(f"  IRP_MJ_CREATE/CLOSE handler: VA 0x{target1:X} (RVA 0x{target1-IMAGE_BASE:X})")

# Actually the exact instruction is at 0x140001724, but let me verify
# From the output: 0x140001724: lea rax, [rip + 0x2d5]
# Size of LEA REX.W rax,[rip+disp32] = 7 bytes
# Next instruction at 0x14000172B
# Target = 0x14000172B + 0x2d5 = 0x140001A00
target_create = 0x14000172B + 0x2d5
print(f"  Corrected: IRP_MJ_CREATE handler VA: 0x{target_create:X} (RVA 0x{target_create-IMAGE_BASE:X})")

# The IOCTL handler: lea rax, [rip + 0x1560] at 0x140001749
# Size = 7, next = 0x140001750
# Target = 0x140001750 + 0x1560 = 0x140002CB0
target_ioctl = 0x140001750 + 0x1560
print(f"  IRP_MJ_DEVICE_CONTROL handler VA: 0x{target_ioctl:X} (RVA 0x{target_ioctl-IMAGE_BASE:X})")

# Now disasm the actual IRP_MJ_CREATE handler
disasm_func(target_create - IMAGE_BASE, 256, "IRP_MJ_CREATE Handler (RVA 0x1A00)")

# ============================================================
# Disasm the IRP_MJ_DEVICE_CONTROL (IOCTL) handler
# ============================================================
disasm_func(target_ioctl - IMAGE_BASE, 256, "IRP_MJ_DEVICE_CONTROL Handler (RVA 0x2CB0)")

# ============================================================
# Function at 0x9150 in .data - the hash that's checked?
# Let's check the data at the hash comparison location
# In the enrollment flow, after 0x3276 call -> 0x130C
# Input is lea rcx, [rsp+0x38] where [rsp+0x38] = something
# and 0xFF0000 was stored at [rsp+0x38]
# ============================================================
print("\n\n" + "="*80)
print("  DATA AT .data+0x150 (RVA 0x9150) - possible hash or config")
print("="*80)

data_off = None
for s in pe.sections:
    if b'.data' in s.Name:
        data_off = s.PointerToRawData
        break

if data_off:
    # Print hex dump around interesting offsets
    for region_name, region_off in [(".data+0x150", 0x150), (".data+0x5D0", 0x5D0), (".data+0x5E0", 0x5E0)]:
        print(f"\n  {region_name}:")
        raw = pe.__data__[data_off + region_off: data_off + region_off + 64]
        for i in range(0, len(raw), 16):
            hex_part = ' '.join(f'{b:02X}' for b in raw[i:i+16])
            ascii_part = ''.join(chr(b) if 32<=b<127 else '.' for b in raw[i:i+16])
            print(f"    {region_off+i:04X}: {hex_part:<48} {ascii_part}")

print("\n\nDONE")
