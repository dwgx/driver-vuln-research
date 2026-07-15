"""
Reverse engineering CorsairLLAccess64.sys driver binary.
Analyzes: DriverEntry, IRP dispatch, IOCTL codes, device symlink, access control.
"""
import pefile
import struct
from capstone import *

DRIVER_PATH = r"D:\Project\report\binaries\CorsairLLAccess64.sys"

pe = pefile.PE(DRIVER_PATH)
image_base = pe.OPTIONAL_HEADER.ImageBase

# Build section map for RVA->offset translation
sections = []
for s in pe.sections:
    sections.append({
        'name': s.Name.decode('utf-8', errors='replace').strip('\x00'),
        'va': s.VirtualAddress,
        'vs': s.Misc_VirtualSize,
        'raw_offset': s.PointerToRawData,
        'raw_size': s.SizeOfRawData,
    })

def rva_to_offset(rva):
    for s in sections:
        if s['va'] <= rva < s['va'] + s['raw_size']:
            return rva - s['va'] + s['raw_offset']
    return None

def va_to_offset(va):
    return rva_to_offset(va - image_base)

def offset_to_rva(offset):
    for s in sections:
        if s['raw_offset'] <= offset < s['raw_offset'] + s['raw_size']:
            return offset - s['raw_offset'] + s['va']
    return None

# Load raw data
with open(DRIVER_PATH, 'rb') as f:
    raw_data = f.read()

# Get imports
imports = {}
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8', errors='replace')
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode('utf-8', errors='replace')
                imports[imp.address] = name
                imports[name] = imp.address

print("=" * 70)
print("CorsairLLAccess64.sys - Reverse Engineering Analysis")
print("=" * 70)
print(f"\nImage Base: 0x{image_base:X}")
print(f"Entry Point RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
print(f"File Size: {len(raw_data)} bytes")

print("\n--- Sections ---")
for s in sections:
    print(f"  {s['name']:8s} VA=0x{s['va']:06X} Size=0x{s['vs']:06X} Raw=0x{s['raw_offset']:06X}")

print("\n--- Imports ---")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode('utf-8', errors='replace')
    print(f"\n  [{dll_name}]")
    for imp in entry.imports:
        if imp.name:
            print(f"    0x{imp.address:X}: {imp.name.decode()}")

# Initialize Capstone for x64
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Find entry point and disassemble DriverEntry
entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
entry_offset = rva_to_offset(entry_rva)
entry_va = image_base + entry_rva

print(f"\n{'=' * 70}")
print(f"DriverEntry at VA 0x{entry_va:X} (offset 0x{entry_offset:X})")
print("=" * 70)

# Disassemble from entry point - generous window
code = raw_data[entry_offset:entry_offset + 0x800]
driver_entry_insns = list(md.disasm(code, entry_va))

# Extract all Unicode strings from the binary
def find_unicode_strings(data, min_len=4):
    """Find UTF-16LE strings in binary data."""
    strings = []
    i = 0
    while i < len(data) - 2:
        # Look for printable ASCII as UTF-16LE
        s = b''
        j = i
        while j < len(data) - 1:
            char = data[j:j+2]
            if len(char) < 2:
                break
            val = struct.unpack('<H', char)[0]
            if 0x20 <= val <= 0x7E:
                s += bytes([val])
                j += 2
            elif val == 0 and len(s) >= min_len:
                # null terminator
                break
            else:
                break
        if len(s) >= min_len:
            strings.append((i, s.decode('ascii', errors='replace')))
        i = j + 2 if len(s) >= min_len else i + 2
    return strings

unicode_strings = find_unicode_strings(raw_data)

print("\n--- Unicode Strings (device/symlink related) ---")
device_strings = []
for offset, s in unicode_strings:
    if 'Device' in s or 'DosDevice' in s or 'Corsair' in s or '\\\\' in s or 'Link' in s:
        rva = offset_to_rva(offset)
        va = image_base + rva if rva else 0
        print(f"  Offset 0x{offset:X} VA 0x{va:X}: \"{s}\"")
        device_strings.append((offset, va, s))

# Look for all UNICODE_STRING references in .rdata/.data
print("\n--- All Interesting Strings ---")
for offset, s in unicode_strings:
    if any(k in s.lower() for k in ['corsair', 'device', 'dos', 'link', 'drv', 'access']):
        rva = offset_to_rva(offset)
        va = image_base + rva if rva else 0
        print(f"  0x{offset:04X} (VA 0x{va:X}): \"{s}\"")

# Disassemble DriverEntry looking for key patterns
print(f"\n{'=' * 70}")
print("DriverEntry Disassembly (first 100 instructions)")
print("=" * 70)

# Track LEA instructions that load string addresses and CALL instructions
lea_targets = []
call_targets = []

for i, insn in enumerate(driver_entry_insns[:150]):
    line = f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}"

    # Annotate calls to imports
    if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
        target = int(insn.op_str, 16)
        if target in imports:
            line += f"  ; {imports[target]}"
        call_targets.append((insn.address, target))

    # Track LEA with RIP-relative addressing
    if insn.mnemonic == 'lea' and '[rip' in insn.op_str:
        # Calculate effective address
        # The operand is like [rip + 0xNNN]
        try:
            disp_str = insn.op_str.split('[rip')[-1].strip(' ]')
            if '+' in disp_str:
                disp = int(disp_str.replace('+', '').strip(), 16)
            elif '-' in disp_str:
                disp = -int(disp_str.replace('-', '').strip(), 16)
            else:
                disp = 0
            ea = insn.address + insn.size + disp
            lea_targets.append((insn.address, ea))
            # Check if it points to a known string
            ea_offset = va_to_offset(ea)
            if ea_offset and ea_offset < len(raw_data):
                line += f"  ; -> VA 0x{ea:X} (offset 0x{ea_offset:X})"
        except:
            pass

    # MOV with large immediate (MajorFunction table setup)
    if insn.mnemonic == 'mov' and 'qword' in insn.op_str:
        line += "  ; potential MajorFunction assignment"

    if i < 100 or 'call' in insn.mnemonic or 'lea' in insn.mnemonic:
        print(line)

# Now look for the dispatch function
# In DriverEntry, MajorFunction[IRP_MJ_DEVICE_CONTROL] = offset 0x70 in driver object
# DriverObject->MajorFunction[14] for IRP_MJ_DEVICE_CONTROL
# Offset = 0x70 + 14*8 = 0x70 + 0x70 = 0xE0

print(f"\n{'=' * 70}")
print("Searching for MajorFunction table assignments in DriverEntry")
print("=" * 70)

dispatch_handler_va = None
create_handler_va = None

for i, insn in enumerate(driver_entry_insns[:200]):
    # Look for MOV [reg + offset], reg/imm patterns
    # MajorFunction starts at offset 0x70 in DRIVER_OBJECT
    # IRP_MJ_CREATE = index 0 -> offset 0x70
    # IRP_MJ_CLOSE = index 2 -> offset 0x80
    # IRP_MJ_DEVICE_CONTROL = index 14 -> offset 0xE0
    op = insn.op_str
    if insn.mnemonic == 'mov' and ('+' in op):
        # Check for 0xe0 offset (IRP_MJ_DEVICE_CONTROL = 14, 0x70 + 14*8 = 0xE0)
        if '0xe0]' in op.lower() or '+ 0xe0]' in op.lower():
            print(f"  IRP_MJ_DEVICE_CONTROL assignment at 0x{insn.address:X}: {insn.mnemonic} {op}")
            # The source register contains the handler address
            # Look back for LEA that loaded that register
            src_reg = op.split(',')[-1].strip()
            for j in range(max(0, i-10), i):
                prev = driver_entry_insns[j]
                if prev.mnemonic == 'lea' and prev.op_str.startswith(src_reg):
                    try:
                        disp_str = prev.op_str.split('[rip')[-1].strip(' ]')
                        if '+' in disp_str:
                            disp = int(disp_str.replace('+', '').strip(), 16)
                        elif '-' in disp_str:
                            disp = -int(disp_str.replace('-', '').strip(), 16)
                        else:
                            disp = 0
                        dispatch_handler_va = prev.address + prev.size + disp
                        print(f"    -> Handler at VA 0x{dispatch_handler_va:X}")
                    except:
                        pass

        # IRP_MJ_CREATE at offset 0x70
        if '0x70]' in op.lower() or '+ 0x70]' in op.lower():
            print(f"  IRP_MJ_CREATE assignment at 0x{insn.address:X}: {insn.mnemonic} {op}")
            src_reg = op.split(',')[-1].strip()
            for j in range(max(0, i-10), i):
                prev = driver_entry_insns[j]
                if prev.mnemonic == 'lea' and prev.op_str.startswith(src_reg):
                    try:
                        disp_str = prev.op_str.split('[rip')[-1].strip(' ]')
                        if '+' in disp_str:
                            disp = int(disp_str.replace('+', '').strip(), 16)
                        elif '-' in disp_str:
                            disp = -int(disp_str.replace('-', '').strip(), 16)
                        else:
                            disp = 0
                        create_handler_va = prev.address + prev.size + disp
                        print(f"    -> Handler at VA 0x{create_handler_va:X}")
                    except:
                        pass

# If we didn't find via specific offsets, do a broader search
# Look for any MOV [reg+large_offset], reg pattern
if not dispatch_handler_va:
    print("\n  Broadening search - looking for all MOV [reg+offset] patterns:")
    for i, insn in enumerate(driver_entry_insns[:200]):
        if insn.mnemonic == 'mov' and '[r' in insn.op_str and '+' in insn.op_str:
            # Extract offset
            try:
                parts = insn.op_str.split('+')
                if len(parts) >= 2:
                    off_part = parts[-1].strip(' ]')
                    if off_part.startswith('0x'):
                        off_val = int(off_part, 16)
                        if 0x70 <= off_val <= 0x138:  # MajorFunction range
                            idx = (off_val - 0x70) // 8
                            irp_names = {0: 'IRP_MJ_CREATE', 2: 'IRP_MJ_CLOSE',
                                        14: 'IRP_MJ_DEVICE_CONTROL'}
                            name = irp_names.get(idx, f'IRP_MJ_{idx}')
                            print(f"    0x{insn.address:X}: {insn.mnemonic} {insn.op_str}  ; {name}")
            except:
                pass

# Alternative: scan for function prologues near entry and look for IOCTL patterns
print(f"\n{'=' * 70}")
print("Scanning entire .text section for IOCTL dispatch patterns")
print("=" * 70)

# Get .text section
text_section = None
for s in pe.sections:
    name = s.Name.decode('utf-8', errors='replace').strip('\x00')
    if name == '.text' or name == 'PAGE':
        text_section = s
        break

if not text_section:
    text_section = pe.sections[0]  # First section is usually code

text_offset = text_section.PointerToRawData
text_size = text_section.SizeOfRawData
text_va = image_base + text_section.VirtualAddress
text_code = raw_data[text_offset:text_offset + text_size]

print(f"  Code section: offset=0x{text_offset:X}, size=0x{text_size:X}, VA=0x{text_va:X}")

# Disassemble entire text section
all_insns = list(md.disasm(text_code, text_va))
print(f"  Total instructions disassembled: {len(all_insns)}")

# Find all CMP/SUB with IOCTL-like immediates (0x80002000 range or METHOD_BUFFERED/NEITHER)
# IOCTL format: bits [31:16]=DeviceType, [15:14]=Access, [13:2]=Function, [1:0]=Method
# Common device types: FILE_DEVICE_UNKNOWN=0x22
ioctl_candidates = []

print("\n--- CMP/SUB instructions with potential IOCTL codes ---")
for insn in all_insns:
    if insn.mnemonic in ('cmp', 'sub'):
        # Look for immediate operand that looks like an IOCTL
        op = insn.op_str
        parts = op.split(',')
        if len(parts) == 2:
            imm_str = parts[1].strip()
            if imm_str.startswith('0x') or imm_str.startswith('-0x'):
                try:
                    val = int(imm_str, 16) & 0xFFFFFFFF
                    # IOCTL codes typically have device type in upper word
                    device_type = (val >> 16) & 0xFFFF
                    access = (val >> 14) & 0x3
                    function = (val >> 2) & 0xFFF
                    method = val & 0x3

                    # Filter for reasonable IOCTL codes
                    if device_type in range(0x20, 0x30) or device_type == 0x8000 or (0x9C00 <= device_type <= 0x9C50):
                        ioctl_candidates.append({
                            'address': insn.address,
                            'value': val,
                            'device_type': device_type,
                            'access': access,
                            'function': function,
                            'method': method,
                            'instruction': f"{insn.mnemonic} {insn.op_str}"
                        })
                        access_str = {0: 'ANY', 1: 'READ', 2: 'WRITE', 3: 'READ|WRITE'}.get(access, '?')
                        method_str = {0: 'BUFFERED', 1: 'IN_DIRECT', 2: 'OUT_DIRECT', 3: 'NEITHER'}.get(method, '?')
                        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
                        print(f"    IOCTL=0x{val:08X} DevType=0x{device_type:X} Access={access_str} Func=0x{function:X} Method={method_str}")
                except:
                    pass

# Also look for comparisons after subtraction (switch-case pattern)
# Compilers often do: sub eax, FIRST_IOCTL; then cmp eax, (LAST-FIRST)/step
print("\n--- Looking for switch-case subtraction patterns ---")
for i, insn in enumerate(all_insns):
    if insn.mnemonic == 'sub' and 'eax' in insn.op_str:
        parts = insn.op_str.split(',')
        if len(parts) == 2:
            imm_str = parts[1].strip()
            if imm_str.startswith('0x'):
                try:
                    val = int(imm_str, 16) & 0xFFFFFFFF
                    if val > 0x1000 and val < 0xFFFF0000:
                        # Check next few instructions for ja/jb (switch bounds check)
                        for j in range(i+1, min(i+5, len(all_insns))):
                            nxt = all_insns[j]
                            if nxt.mnemonic in ('ja', 'jae', 'jb', 'jbe', 'cmp'):
                                print(f"  0x{insn.address:X}: sub eax, 0x{val:X} (potential switch base IOCTL)")
                                print(f"    followed by: {nxt.mnemonic} {nxt.op_str}")
                                break
                except:
                    pass

# Now analyze the dispatch handler area more carefully
# Look for the function that handles IRP_MJ_DEVICE_CONTROL
# It will reference IoCompleteRequest and check IoControlCode at IRP offset 0x18 in IO_STACK_LOCATION

print(f"\n{'=' * 70}")
print("Analyzing potential dispatch functions")
print("=" * 70)

# Find all function prologues (push rbp; mov rbp, rsp or sub rsp, XX)
func_starts = []
for i, insn in enumerate(all_insns):
    if i == 0:
        func_starts.append(insn.address)
        continue
    # Common x64 prologue patterns
    if insn.mnemonic == 'mov' and insn.op_str == 'rbp, rsp':
        if i > 0 and all_insns[i-1].mnemonic == 'push' and 'rbp' in all_insns[i-1].op_str:
            func_starts.append(all_insns[i-1].address)
    elif insn.mnemonic == 'sub' and 'rsp' in insn.op_str and i > 0:
        # Check if preceded by push or if it's at an aligned address
        if all_insns[i-1].mnemonic in ('push', 'mov') or (insn.address % 16 == 0):
            if insn.address % 4 == 0:  # Must be aligned
                func_starts.append(insn.address)

print(f"  Found {len(func_starts)} potential function starts")

# For each IOCTL candidate, find the containing function and analyze it
ioctl_functions = set()
for ic in ioctl_candidates:
    # Find which function contains this IOCTL comparison
    for j, fs in enumerate(func_starts):
        if j + 1 < len(func_starts):
            if fs <= ic['address'] < func_starts[j+1]:
                ioctl_functions.add(fs)
                break
        else:
            if fs <= ic['address']:
                ioctl_functions.add(fs)

print(f"  IOCTL handling found in {len(ioctl_functions)} function(s)")

# Analyze each IOCTL-handling function in detail
for func_va in sorted(ioctl_functions):
    func_offset = va_to_offset(func_va)
    if not func_offset:
        continue

    # Find function end (next function start or ret)
    func_end = func_va + 0x1000  # max size
    for fs in sorted(func_starts):
        if fs > func_va:
            func_end = fs
            break

    func_size = func_end - func_va
    func_code = raw_data[func_offset:func_offset + func_size]
    func_insns = list(md.disasm(func_code, func_va))

    print(f"\n  --- Function at 0x{func_va:X} (size ~0x{func_size:X}) ---")

    # Find buffer size checks (cmp with small values for InputBufferLength)
    buffer_checks = []
    ioctl_checks = []
    api_calls = []

    for i, insn in enumerate(func_insns):
        # IOCTL code comparisons
        if insn.mnemonic in ('cmp', 'sub'):
            parts = insn.op_str.split(',')
            if len(parts) == 2:
                imm_str = parts[1].strip()
                if imm_str.startswith('0x'):
                    try:
                        val = int(imm_str, 16) & 0xFFFFFFFF
                        device_type = (val >> 16) & 0xFFFF
                        if device_type in range(0x20, 0x30) or device_type == 0x8000 or (0x9C00 <= device_type <= 0x9C50):
                            ioctl_checks.append((insn.address, val, insn.mnemonic))
                        elif val < 0x200 and val >= 4:
                            # Could be buffer size check
                            buffer_checks.append((insn.address, val, parts[0].strip()))
                    except:
                        pass

        # API calls
        if insn.mnemonic == 'call':
            if insn.op_str.startswith('0x'):
                try:
                    target = int(insn.op_str, 16)
                    if target in imports:
                        api_calls.append((insn.address, imports[target]))
                except:
                    pass
            # Indirect calls through IAT
            elif '[rip' in insn.op_str:
                try:
                    disp_str = insn.op_str.split('[rip')[-1].strip(' ]')
                    if '+' in disp_str:
                        disp = int(disp_str.replace('+', '').strip(), 16)
                    elif '-' in disp_str:
                        disp = -int(disp_str.replace('-', '').strip(), 16)
                    else:
                        disp = 0
                    call_target_va = insn.address + insn.size + disp
                    if call_target_va in imports:
                        api_calls.append((insn.address, imports[call_target_va]))
                    else:
                        # Check IAT - read the pointer
                        ct_offset = va_to_offset(call_target_va)
                        if ct_offset and ct_offset + 8 <= len(raw_data):
                            ptr = struct.unpack('<Q', raw_data[ct_offset:ct_offset+8])[0]
                            if ptr in imports:
                                api_calls.append((insn.address, imports[ptr]))
                except:
                    pass

    if ioctl_checks:
        print(f"    IOCTL comparisons:")
        for addr, val, mnem in ioctl_checks:
            access = (val >> 14) & 0x3
            function = (val >> 2) & 0xFFF
            method = val & 0x3
            access_str = {0: 'ANY', 1: 'READ', 2: 'WRITE', 3: 'READ|WRITE'}.get(access, '?')
            method_str = {0: 'BUFFERED', 1: 'IN_DIRECT', 2: 'OUT_DIRECT', 3: 'NEITHER'}.get(method, '?')
            print(f"      0x{addr:X}: {mnem} -> IOCTL 0x{val:08X} (Func=0x{function:X}, {access_str}, {method_str})")

    if buffer_checks:
        print(f"    Buffer size checks:")
        for addr, val, reg in buffer_checks:
            print(f"      0x{addr:X}: cmp {reg}, 0x{val:X} ({val} bytes)")

    if api_calls:
        print(f"    API calls:")
        for addr, name in api_calls:
            print(f"      0x{addr:X}: {name}")

# Now let's look at ALL calls in the driver to understand the full picture
print(f"\n{'=' * 70}")
print("All imported API calls in the driver")
print("=" * 70)

all_api_calls = []
for insn in all_insns:
    if insn.mnemonic == 'call':
        if '[rip' in insn.op_str:
            try:
                disp_str = insn.op_str.split('[rip')[-1].strip(' ]')
                if '+' in disp_str:
                    disp = int(disp_str.replace('+', '').strip(), 16)
                elif '-' in disp_str:
                    disp = -int(disp_str.replace('-', '').strip(), 16)
                else:
                    disp = 0
                call_target_va = insn.address + insn.size + disp
                # Read IAT entry
                ct_offset = va_to_offset(call_target_va)
                if ct_offset and ct_offset + 8 <= len(raw_data):
                    ptr = struct.unpack('<Q', raw_data[ct_offset:ct_offset+8])[0]
                    if ptr in imports:
                        all_api_calls.append((insn.address, imports[ptr]))
            except:
                pass

# Group by API
from collections import defaultdict
api_usage = defaultdict(list)
for addr, name in all_api_calls:
    api_usage[name].append(addr)

for name in sorted(api_usage.keys()):
    addrs = api_usage[name]
    print(f"  {name}: called at {', '.join(f'0x{a:X}' for a in addrs)}")

# Deep analysis - look at specific interesting areas
print(f"\n{'=' * 70}")
print("Detailed DriverEntry flow analysis")
print("=" * 70)

# Print full DriverEntry disassembly with annotations
for i, insn in enumerate(driver_entry_insns[:200]):
    annotation = ""

    if insn.mnemonic == 'call' and '[rip' in insn.op_str:
        try:
            disp_str = insn.op_str.split('[rip')[-1].strip(' ]')
            if '+' in disp_str:
                disp = int(disp_str.replace('+', '').strip(), 16)
            elif '-' in disp_str:
                disp = -int(disp_str.replace('-', '').strip(), 16)
            else:
                disp = 0
            call_target_va = insn.address + insn.size + disp
            ct_offset = va_to_offset(call_target_va)
            if ct_offset and ct_offset + 8 <= len(raw_data):
                ptr = struct.unpack('<Q', raw_data[ct_offset:ct_offset+8])[0]
                if ptr in imports:
                    annotation = f"  ; << {imports[ptr]} >>"
        except:
            pass

    if insn.mnemonic == 'lea' and '[rip' in insn.op_str:
        try:
            disp_str = insn.op_str.split('[rip')[-1].strip(' ]')
            if '+' in disp_str:
                disp = int(disp_str.replace('+', '').strip(), 16)
            elif '-' in disp_str:
                disp = -int(disp_str.replace('-', '').strip(), 16)
            else:
                disp = 0
            ea = insn.address + insn.size + disp
            ea_offset = va_to_offset(ea)
            # Check if points to a unicode string
            if ea_offset:
                for soff, sval in device_strings:
                    if abs(soff - ea_offset) < 16:
                        annotation = f"  ; -> \"{sval}\""
                        break
                if not annotation:
                    # Try reading as UNICODE_STRING struct (Length, MaxLength, Buffer pointer)
                    if ea_offset + 16 <= len(raw_data):
                        length = struct.unpack('<H', raw_data[ea_offset:ea_offset+2])[0]
                        max_length = struct.unpack('<H', raw_data[ea_offset+2:ea_offset+4])[0]
                        if 4 < length < 200 and length <= max_length:
                            annotation = f"  ; -> UNICODE_STRING(len={length}) at VA 0x{ea:X}"
        except:
            pass

    if insn.mnemonic == 'mov' and '+' in insn.op_str:
        # Annotate MajorFunction assignments
        try:
            if '0x70]' in insn.op_str:
                annotation = "  ; DriverObject->MajorFunction[IRP_MJ_CREATE]"
            elif '0x78]' in insn.op_str:
                annotation = "  ; DriverObject->MajorFunction[IRP_MJ_CREATE_NAMED_PIPE]"
            elif '0x80]' in insn.op_str:
                annotation = "  ; DriverObject->MajorFunction[IRP_MJ_CLOSE]"
            elif '0xe0]' in insn.op_str:
                annotation = "  ; DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]"
            elif '0x68]' in insn.op_str:
                annotation = "  ; DriverObject->DriverUnload"
        except:
            pass

    print(f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}{annotation}")

# Analyze the SeQueryInformationToken usage
print(f"\n{'=' * 70}")
print("SeQueryInformationToken usage analysis (access control)")
print("=" * 70)

se_query_addrs = api_usage.get('SeQueryInformationToken', [])
if se_query_addrs:
    for call_addr in se_query_addrs:
        print(f"\n  Call at 0x{call_addr:X}")
        # Find the function containing this call
        containing_func = None
        for fs in sorted(func_starts, reverse=True):
            if fs <= call_addr:
                containing_func = fs
                break

        if containing_func:
            print(f"  In function starting at 0x{containing_func:X}")
            func_offset = va_to_offset(containing_func)
            func_code = raw_data[func_offset:func_offset + 0x400]
            func_insns = list(md.disasm(func_code, containing_func))

            # Print context around the call
            for i, insn in enumerate(func_insns):
                if abs(insn.address - call_addr) < 0x40:
                    ann = ""
                    if insn.mnemonic == 'call' and '[rip' in insn.op_str:
                        try:
                            disp_str = insn.op_str.split('[rip')[-1].strip(' ]')
                            if '+' in disp_str:
                                disp = int(disp_str.replace('+', '').strip(), 16)
                            elif '-' in disp_str:
                                disp = -int(disp_str.replace('-', '').strip(), 16)
                            else:
                                disp = 0
                            ct_va = insn.address + insn.size + disp
                            ct_off = va_to_offset(ct_va)
                            if ct_off and ct_off + 8 <= len(raw_data):
                                ptr = struct.unpack('<Q', raw_data[ct_off:ct_off+8])[0]
                                if ptr in imports:
                                    ann = f"  ; {imports[ptr]}"
                        except:
                            pass
                    # Check for TOKEN_INFORMATION_CLASS values
                    if insn.mnemonic == 'mov' and 'edx' in insn.op_str.split(',')[0]:
                        try:
                            val_str = insn.op_str.split(',')[1].strip()
                            if val_str.isdigit() or val_str.startswith('0x'):
                                val = int(val_str, 0)
                                token_classes = {1: 'TokenUser', 2: 'TokenGroups',
                                               3: 'TokenPrivileges', 25: 'TokenElevation',
                                               20: 'TokenStatistics', 17: 'TokenOrigin'}
                                if val in token_classes:
                                    ann = f"  ; {token_classes[val]}"
                        except:
                            pass
                    print(f"    0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}{ann}")
else:
    print("  SeQueryInformationToken not found in imports")
    # Check for similar access control APIs
    for name in ['SeAccessCheck', 'IoCheckShareAccess', 'SeSinglePrivilegeCheck',
                 'PsGetCurrentProcess', 'PsLookupProcessByProcessId',
                 'ZwOpenProcessTokenEx', 'ZwQueryInformationToken']:
        if name in api_usage:
            print(f"  Found: {name} at {', '.join(f'0x{a:X}' for a in api_usage[name])}")

# Final summary
print(f"\n{'=' * 70}")
print("SUMMARY - IOCTL TABLE")
print("=" * 70)

if ioctl_candidates:
    # Deduplicate
    seen = set()
    unique_ioctls = []
    for ic in ioctl_candidates:
        if ic['value'] not in seen:
            seen.add(ic['value'])
            unique_ioctls.append(ic)

    unique_ioctls.sort(key=lambda x: x['value'])

    print(f"\n{'IOCTL Code':<14} {'DevType':<8} {'Function':<10} {'Access':<12} {'Method':<12} {'Location'}")
    print("-" * 80)
    for ic in unique_ioctls:
        access_str = {0: 'ANY', 1: 'READ', 2: 'WRITE', 3: 'READ|WRITE'}.get(ic['access'], '?')
        method_str = {0: 'BUFFERED', 1: 'IN_DIRECT', 2: 'OUT_DIRECT', 3: 'NEITHER'}.get(ic['method'], '?')
        print(f"0x{ic['value']:08X}   0x{ic['device_type']:04X}   0x{ic['function']:04X}     {access_str:<12} {method_str:<12} 0x{ic['address']:X}")
else:
    print("  No standard IOCTL codes found via CMP/SUB pattern")
    print("  Trying alternative: looking for all large immediates in comparisons...")

    # Broader search
    for insn in all_insns:
        if insn.mnemonic in ('cmp', 'sub', 'xor'):
            parts = insn.op_str.split(',')
            if len(parts) == 2:
                imm_str = parts[1].strip()
                if imm_str.startswith('0x'):
                    try:
                        val = int(imm_str, 16) & 0xFFFFFFFF
                        if 0x80000000 <= val <= 0xA0000000 or 0x220000 <= val <= 0x230000:
                            print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str} -> 0x{val:08X}")
                    except:
                        pass

print(f"\n{'=' * 70}")
print("DEVICE SYMLINK")
print("=" * 70)
for offset, va, s in device_strings:
    print(f"  \"{s}\"  (VA 0x{va:X})")

print(f"\n{'=' * 70}")
print("END OF ANALYSIS")
print("=" * 70)
