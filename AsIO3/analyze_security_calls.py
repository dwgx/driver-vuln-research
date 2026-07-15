import pefile
import struct
from capstone import *

pe = pefile.PE(r"D:\Project\report\AsIO3\Asusgio3.sys")
IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase

def rva_to_offset(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.SizeOfRawData:
            return rva - s.VirtualAddress + s.PointerToRawData
    return None

def get_bytes_at_rva(rva, size):
    off = rva_to_offset(rva)
    if off is None:
        return None
    return pe.__data__[off:off+size]

import_thunks = {}
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                iat_rva = imp.address - IMAGE_BASE
                import_thunks[iat_rva] = imp.name.decode('utf-8', errors='replace')

known_strings = {
    0x7B40: '\\Device\\Asusgio3',
    0x7B70: '\\DosDevices\\Asusgio3',
    0x83F0: 'SDDL: "D:P(A;;GA;;;SY)(A;;GA;;;BA)"',
    0x7C60: '\\Device\\PhysicalMemory',
}

def disasm_range(rva, size, label=""):
    code = get_bytes_at_rva(rva, size)
    if code is None:
        print(f"  Cannot read bytes at RVA 0x{rva:X}")
        return
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    print(f"\n{'='*70}")
    print(f"=== {label} (RVA 0x{rva:X}) ===")
    print(f"{'='*70}")
    for insn in md.disasm(code, IMAGE_BASE + rva):
        line = f"  0x{insn.address:X}: {insn.mnemonic:10s} {insn.op_str}"
        if insn.mnemonic in ('call', 'jmp') and 'rax' not in insn.op_str and 'r10' not in insn.op_str and 'r11' not in insn.op_str:
            if 'qword ptr [rip' in insn.op_str:
                next_addr = insn.address + insn.size
                for op in insn.operands:
                    if op.type == 2:
                        target = next_addr + op.mem.disp
                        target_rva = target - IMAGE_BASE
                        if target_rva in import_thunks:
                            line += f"  ; {import_thunks[target_rva]}"
                        else:
                            line += f"  ; [0x{target_rva:X}]"
            elif insn.op_str.startswith('0x'):
                target = int(insn.op_str, 16)
                target_rva = target - IMAGE_BASE
                line += f"  ; RVA 0x{target_rva:X}"
        elif insn.mnemonic == 'lea' and 'rip' in insn.op_str:
            next_addr = insn.address + insn.size
            for op in insn.operands:
                if op.type == 2 and op.mem.base != 0:
                    target = next_addr + op.mem.disp
                    target_rva = target - IMAGE_BASE
                    if target_rva in known_strings:
                        line += f"  ; -> {known_strings[target_rva]}"
                    else:
                        line += f"  ; -> RVA 0x{target_rva:X}"
        print(line)
        if insn.mnemonic == 'ret':
            break

# 0xB170 - called as initialization before IoCreateDevice
disasm_range(0xB170, 0x80, "sub_B170 (pre-IoCreateDevice init)")

# Now let's search for where ZwSetSecurityObject is called
# IAT RVA for ZwSetSecurityObject = 0x8188
# Look for calls to [rip+offset] that resolve to 0x8188
print("\n\n")
print("="*70)
print("=== Searching for ZwSetSecurityObject call sites ===")
print("="*70)

# Search all code sections
code_sections = []
for s in pe.sections:
    name = s.Name.decode('utf-8', errors='replace').rstrip('\x00')
    chars = s.Characteristics
    if chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
        code_sections.append((name, s.VirtualAddress, s.Misc_VirtualSize))

for sec_name, sec_va, sec_size in code_sections:
    code = get_bytes_at_rva(sec_va, sec_size)
    if code is None:
        continue
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for insn in md.disasm(code, IMAGE_BASE + sec_va):
        if insn.mnemonic == 'call' and 'qword ptr [rip' in insn.op_str:
            next_addr = insn.address + insn.size
            for op in insn.operands:
                if op.type == 2:
                    target = next_addr + op.mem.disp
                    target_rva = target - IMAGE_BASE
                    if target_rva == 0x8188:  # ZwSetSecurityObject
                        call_rva = insn.address - IMAGE_BASE
                        print(f"  ZwSetSecurityObject called at RVA 0x{call_rva:X} (section {sec_name})")

# Also find IoCreateDevice calls
print("\n")
print("=== Searching for IoCreateDevice call sites ===")
for sec_name, sec_va, sec_size in code_sections:
    code = get_bytes_at_rva(sec_va, sec_size)
    if code is None:
        continue
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for insn in md.disasm(code, IMAGE_BASE + sec_va):
        if insn.mnemonic == 'call' and 'qword ptr [rip' in insn.op_str:
            next_addr = insn.address + insn.size
            for op in insn.operands:
                if op.type == 2:
                    target = next_addr + op.mem.disp
                    target_rva = target - IMAGE_BASE
                    if target_rva == 0x8198:  # IoCreateDevice
                        call_rva = insn.address - IMAGE_BASE
                        print(f"  IoCreateDevice called at RVA 0x{call_rva:X} (section {sec_name})")

# Find RtlCreateSecurityDescriptor calls
print("\n")
print("=== Searching for RtlCreateSecurityDescriptor call sites ===")
for sec_name, sec_va, sec_size in code_sections:
    code = get_bytes_at_rva(sec_va, sec_size)
    if code is None:
        continue
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for insn in md.disasm(code, IMAGE_BASE + sec_va):
        if insn.mnemonic == 'call' and 'qword ptr [rip' in insn.op_str:
            next_addr = insn.address + insn.size
            for op in insn.operands:
                if op.type == 2:
                    target = next_addr + op.mem.disp
                    target_rva = target - IMAGE_BASE
                    if target_rva == 0x81E8:  # RtlCreateSecurityDescriptor
                        call_rva = insn.address - IMAGE_BASE
                        print(f"  RtlCreateSecurityDescriptor called at RVA 0x{call_rva:X} (section {sec_name})")

# Find RtlSetDaclSecurityDescriptor calls
print("\n")
print("=== Searching for RtlSetDaclSecurityDescriptor call sites ===")
for sec_name, sec_va, sec_size in code_sections:
    code = get_bytes_at_rva(sec_va, sec_size)
    if code is None:
        continue
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for insn in md.disasm(code, IMAGE_BASE + sec_va):
        if insn.mnemonic == 'call' and 'qword ptr [rip' in insn.op_str:
            next_addr = insn.address + insn.size
            for op in insn.operands:
                if op.type == 2:
                    target = next_addr + op.mem.disp
                    target_rva = target - IMAGE_BASE
                    if target_rva == 0x8220:  # RtlSetDaclSecurityDescriptor
                        call_rva = insn.address - IMAGE_BASE
                        print(f"  RtlSetDaclSecurityDescriptor called at RVA 0x{call_rva:X} (section {sec_name})")

# Find RtlAddAccessAllowedAce calls
print("\n")
print("=== Searching for RtlAddAccessAllowedAce call sites ===")
for sec_name, sec_va, sec_size in code_sections:
    code = get_bytes_at_rva(sec_va, sec_size)
    if code is None:
        continue
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for insn in md.disasm(code, IMAGE_BASE + sec_va):
        if insn.mnemonic == 'call' and 'qword ptr [rip' in insn.op_str:
            next_addr = insn.address + insn.size
            for op in insn.operands:
                if op.type == 2:
                    target = next_addr + op.mem.disp
                    target_rva = target - IMAGE_BASE
                    if target_rva == 0x8208:  # RtlAddAccessAllowedAce
                        call_rva = insn.address - IMAGE_BASE
                        print(f"  RtlAddAccessAllowedAce called at RVA 0x{call_rva:X} (section {sec_name})")

# Find references to SDDL string at RVA 0x83F0
print("\n")
print("=== Searching for references to SDDL string (RVA 0x83F0) ===")
sddl_addr = IMAGE_BASE + 0x83F0
for sec_name, sec_va, sec_size in code_sections:
    code = get_bytes_at_rva(sec_va, sec_size)
    if code is None:
        continue
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for insn in md.disasm(code, IMAGE_BASE + sec_va):
        if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
            next_addr = insn.address + insn.size
            for op in insn.operands:
                if op.type == 2 and op.mem.base != 0:
                    target = next_addr + op.mem.disp
                    if target == sddl_addr:
                        ref_rva = insn.address - IMAGE_BASE
                        print(f"  LEA to SDDL string at RVA 0x{ref_rva:X} (section {sec_name})")
