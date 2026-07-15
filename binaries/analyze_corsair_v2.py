"""
Enhanced reverse engineering of CorsairLLAccess64.sys - Phase 2.
Deep analysis of the real DriverEntry (0x140001B58), dispatch handler, and create handler.
"""
import pefile
import struct
from capstone import *
from collections import defaultdict

DRIVER_PATH = r"D:\Project\report\binaries\CorsairLLAccess64.sys"

pe = pefile.PE(DRIVER_PATH)
image_base = pe.OPTIONAL_HEADER.ImageBase

with open(DRIVER_PATH, 'rb') as f:
    raw_data = f.read()

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

# Build IAT mapping
iat_map = {}  # VA of IAT slot -> function name
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                # The IAT slot VA
                iat_map[imp.address] = imp.name.decode('utf-8', errors='replace')

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def disasm_at(va, size=0x1000):
    offset = va_to_offset(va)
    if not offset:
        return []
    code = raw_data[offset:offset + size]
    return list(md.disasm(code, va))

def resolve_call(insn):
    """Resolve a call instruction to an import name."""
    if insn.mnemonic != 'call':
        return None
    if '[rip' in insn.op_str:
        try:
            disp_str = insn.op_str.split('[rip')[-1].strip(' ]')
            if '+' in disp_str:
                disp = int(disp_str.replace('+', '').strip(), 16)
            elif '-' in disp_str:
                disp = -int(disp_str.replace('-', '').strip(), 16)
            else:
                disp = 0
            target_va = insn.address + insn.size + disp
            if target_va in iat_map:
                return iat_map[target_va]
        except:
            pass
    return None

def resolve_lea(insn):
    """Resolve a LEA [rip+disp] to effective address."""
    if insn.mnemonic != 'lea' or '[rip' not in insn.op_str:
        return None
    try:
        disp_str = insn.op_str.split('[rip')[-1].strip(' ]')
        if '+' in disp_str:
            disp = int(disp_str.replace('+', '').strip(), 16)
        elif '-' in disp_str:
            disp = -int(disp_str.replace('-', '').strip(), 16)
        else:
            disp = 0
        return insn.address + insn.size + disp
    except:
        return None

def read_unicode_at_offset(offset, max_len=200):
    """Read a UTF-16LE string at given file offset."""
    result = b''
    i = offset
    while i < min(offset + max_len*2, len(raw_data)) - 1:
        char = struct.unpack('<H', raw_data[i:i+2])[0]
        if char == 0:
            break
        if 0x20 <= char <= 0x7E:
            result += bytes([char])
        else:
            break
        i += 2
    return result.decode('ascii', errors='replace') if result else None

# ================================================================
# The real DriverEntry is at 0x140001B58 (called from INIT:0x140006000)
# ================================================================
print("=" * 70)
print("REAL DriverEntry function at 0x140001B58")
print("=" * 70)

init_func = disasm_at(0x140001B58, 0x500)

print("\nFull annotated disassembly:")
for i, insn in enumerate(init_func):
    if insn.mnemonic == 'int3':
        print(f"  --- function boundary ---")
        break

    ann = ""

    # Resolve calls
    api = resolve_call(insn)
    if api:
        ann = f"  ; << {api} >>"

    # Resolve LEA targets
    if insn.mnemonic == 'lea':
        ea = resolve_lea(insn)
        if ea:
            ea_off = va_to_offset(ea)
            if ea_off:
                s = read_unicode_at_offset(ea_off)
                if s:
                    ann = f'  ; -> "{s}"'
                else:
                    # Try as a UNICODE_STRING struct
                    if ea_off + 16 <= len(raw_data):
                        ulen = struct.unpack('<H', raw_data[ea_off:ea_off+2])[0]
                        umaxlen = struct.unpack('<H', raw_data[ea_off+2:ea_off+4])[0]
                        if 2 < ulen < 300 and ulen <= umaxlen:
                            # Read the buffer pointer (offset +8 in x64 UNICODE_STRING)
                            buf_ptr = struct.unpack('<Q', raw_data[ea_off+8:ea_off+16])[0]
                            ann = f"  ; -> UNICODE_STRING(len={ulen}) buf=0x{buf_ptr:X}"
                        else:
                            ann = f"  ; -> VA 0x{ea:X}"
            else:
                ann = f"  ; -> VA 0x{ea:X}"

    # MajorFunction assignments
    if insn.mnemonic == 'mov' and '+' in insn.op_str:
        op = insn.op_str.lower()
        if '0x70]' in op:
            ann = "  ; MajorFunction[IRP_MJ_CREATE]"
        elif '0x80]' in op:
            ann = "  ; MajorFunction[IRP_MJ_CLOSE]"
        elif '0x88]' in op:
            ann = "  ; MajorFunction[IRP_MJ_READ]"
        elif '0xe0]' in op:
            ann = "  ; MajorFunction[IRP_MJ_DEVICE_CONTROL]"
        elif '0x68]' in op:
            ann = "  ; DriverObject->DriverUnload"

    # Direct call to internal function
    if insn.mnemonic == 'call' and not api and insn.op_str.startswith('0x'):
        target = int(insn.op_str, 16)
        ann = f"  ; internal sub_0x{target:X}"

    print(f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}{ann}")

# ================================================================
# Now analyze the dispatch handler at 0x1400010DC more carefully
# ================================================================
print(f"\n{'=' * 70}")
print("IRP_MJ_DEVICE_CONTROL Dispatch Handler - Deep Analysis")
print("=" * 70)

# The dispatch function handles IOCTLs
# Let's look at the function from 0x1400010DC more carefully
# First the sub at the start: it processes IoControlCode from the IRP

dispatch_insns = disasm_at(0x1400010DC, 0xA00)

# Track the IOCTL switch logic
# In x64 Windows, IoControlCode is at IRP->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.IoControlCode
# which is typically loaded from [r8+XX] or through IoGetCurrentIrpStackLocation

print("\nFull dispatch handler (annotated):")
current_ioctl_context = None

for i, insn in enumerate(dispatch_insns):
    if insn.mnemonic == 'int3' and i > 10:
        # Check if this is a padding between functions or just alignment
        if i + 1 < len(dispatch_insns) and dispatch_insns[i+1].mnemonic == 'int3':
            break
        continue

    ann = ""
    api = resolve_call(insn)
    if api:
        ann = f"  ; << {api} >>"

    if insn.mnemonic == 'lea':
        ea = resolve_lea(insn)
        if ea:
            ea_off = va_to_offset(ea)
            if ea_off:
                s = read_unicode_at_offset(ea_off)
                if s:
                    ann = f'  ; -> "{s}"'
                else:
                    ann = f"  ; -> 0x{ea:X}"

    # IOCTL comparisons
    if insn.mnemonic in ('cmp', 'sub') and '0x22' in insn.op_str:
        parts = insn.op_str.split(',')
        if len(parts) == 2:
            try:
                val = int(parts[1].strip(), 16) & 0xFFFFFFFF
                if (val >> 16) & 0xFFFF == 0x22:
                    func_code = (val >> 2) & 0xFFF
                    access = (val >> 14) & 0x3
                    method = val & 0x3
                    access_s = {0:'ANY',1:'READ',2:'WRITE',3:'RW'}[access]
                    method_s = {0:'BUFFERED',1:'IN_DIRECT',2:'OUT_DIRECT',3:'NEITHER'}[method]
                    ann = f"  ; IOCTL 0x{val:08X} Func=0x{func_code:X} {access_s} {method_s}"
            except:
                pass

    # Buffer size checks
    if insn.mnemonic == 'cmp':
        parts = insn.op_str.split(',')
        if len(parts) == 2:
            try:
                imm = parts[1].strip()
                if imm.startswith('0x'):
                    val = int(imm, 16)
                    if 4 <= val <= 0x100:
                        ann = f"  ; size check: {val} bytes"
            except:
                pass

    if i < 300:  # Print first 300 instructions
        print(f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}{ann}")

# ================================================================
# Analyze the IRP_MJ_CREATE handler
# From DriverEntry, look for what's assigned to MajorFunction[0] offset 0x70
# ================================================================
print(f"\n{'=' * 70}")
print("Looking for IRP_MJ_CREATE handler")
print("=" * 70)

# The real DriverEntry is at 0x140001B58. Let's look for the MOV pattern
# that assigns to offset 0x70 from the DriverObject pointer (first param = rcx)
for i, insn in enumerate(init_func):
    if insn.mnemonic == 'int3':
        break
    op = insn.op_str.lower()
    # Look for qword ptr [reg + 0x70], reg
    if insn.mnemonic == 'mov' and '0x70]' in op:
        print(f"  Found MajorFunction[CREATE] assignment: 0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
        # The source should be a register loaded via LEA earlier
        src = insn.op_str.split(',')[-1].strip()
        print(f"  Source register: {src}")
        # Search backward for LEA loading that register
        for j in range(i-1, max(0, i-15), -1):
            prev = init_func[j]
            if prev.mnemonic == 'lea' and prev.op_str.startswith(src):
                ea = resolve_lea(prev)
                if ea:
                    print(f"  IRP_MJ_CREATE handler at: 0x{ea:X}")
    if insn.mnemonic == 'mov' and '0x80]' in op:
        print(f"  Found MajorFunction[CLOSE] assignment: 0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic == 'mov' and '0xe0]' in op:
        print(f"  Found MajorFunction[DEVICE_CONTROL] assignment: 0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic == 'mov' and '0x68]' in op:
        print(f"  Found DriverUnload assignment: 0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")

# ================================================================
# The SeQueryInformationToken is called at 0x14000114F and 0x14000117D
# Let's analyze that area in detail
# ================================================================
print(f"\n{'=' * 70}")
print("Access Control Analysis - SeQueryInformationToken calls")
print("=" * 70)

# Disassemble around 0x14000114F with more context
access_check_insns = disasm_at(0x1400010DC, 0x200)

print("\nFunction containing SeQueryInformationToken (0x1400010DC region):")
for insn in access_check_insns:
    ann = ""
    api = resolve_call(insn)
    if api:
        ann = f"  ; << {api} >>"

    # TOKEN_INFORMATION_CLASS in edx (second param)
    if insn.mnemonic == 'mov':
        parts = insn.op_str.split(',')
        if len(parts) == 2:
            dst = parts[0].strip()
            src = parts[1].strip()
            if dst in ('edx', 'r8d', 'dl', 'rdx'):
                try:
                    val = int(src, 0)
                    token_classes = {
                        1: 'TokenUser', 2: 'TokenGroups', 3: 'TokenPrivileges',
                        4: 'TokenOwner', 5: 'TokenPrimaryGroup', 17: 'TokenOrigin',
                        20: 'TokenStatistics', 25: 'TokenElevation',
                        26: 'TokenElevationType', 29: 'TokenIsAppContainer'
                    }
                    if val in token_classes:
                        ann = f"  ; TOKEN_INFORMATION_CLASS = {token_classes[val]}"
                except:
                    pass

    if insn.mnemonic == 'lea':
        ea = resolve_lea(insn)
        if ea:
            ea_off = va_to_offset(ea)
            if ea_off:
                s = read_unicode_at_offset(ea_off)
                if s:
                    ann = f'  ; -> "{s}"'

    print(f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}{ann}")

# ================================================================
# Examine full IOCTL switch - look for additional IOCTLs via delta pattern
# The first SUB 0x225348 means the base IOCTL is 0x225348
# Subsequent comparisons after subtraction indicate delta from base
# ================================================================
print(f"\n{'=' * 70}")
print("IOCTL Switch-Case Reconstruction")
print("=" * 70)

# Look at what happens after sub eax, 0x225348
base_ioctl = 0x225348
print(f"\nBase IOCTL (first SUB): 0x{base_ioctl:08X}")
print("Looking for jump table or cascading comparisons after 0x140001235...\n")

# Find all CMP/JE/JNE/JA after the first SUB
in_switch = False
for i, insn in enumerate(dispatch_insns):
    if insn.address == 0x140001235:
        in_switch = True
    if in_switch and insn.address > 0x140001235 + 0x200:
        break
    if in_switch:
        ann = ""
        if insn.mnemonic in ('je', 'jne', 'ja', 'jae', 'jb', 'jbe', 'jz', 'jnz'):
            ann = f"  ; branch target"
        if insn.mnemonic == 'cmp':
            parts = insn.op_str.split(',')
            if len(parts) == 2:
                try:
                    val = int(parts[1].strip(), 16)
                    # After SUB base, comparisons give delta
                    computed_ioctl = base_ioctl + val
                    device_type = (computed_ioctl >> 16) & 0xFFFF
                    if device_type == 0x22:
                        func_code = (computed_ioctl >> 2) & 0xFFF
                        access = (computed_ioctl >> 14) & 0x3
                        method = computed_ioctl & 0x3
                        access_s = {0:'ANY',1:'READ',2:'WRITE',3:'RW'}[access]
                        method_s = {0:'BUFFERED',1:'IN_DIRECT',2:'OUT_DIRECT',3:'NEITHER'}[method]
                        ann = f"  ; delta=0x{val:X} -> IOCTL 0x{computed_ioctl:08X} Func=0x{func_code:X} {access_s} {method_s}"
                except:
                    pass
        if insn.mnemonic == 'sub' and 'eax' in insn.op_str:
            parts = insn.op_str.split(',')
            if len(parts) == 2:
                try:
                    val = int(parts[1].strip(), 16)
                    if val > 0x1000:
                        ann = f"  ; new SUB base: 0x{val:08X}"
                except:
                    pass
        api = resolve_call(insn)
        if api:
            ann = f"  ; << {api} >>"
        print(f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}{ann}")

# ================================================================
# Look at .rdata for the device name string construction
# The driver uses RtlInitUnicodeString + wcsncat_s to build the name
# ================================================================
print(f"\n{'=' * 70}")
print("Device Name / Symlink String Analysis")
print("=" * 70)

# Read the .rdata section looking for the device name parts
rdata_offset = None
for s in sections:
    if s['name'] == '.rdata':
        rdata_offset = s['raw_offset']
        rdata_size = s['raw_size']
        rdata_va = image_base + s['va']
        break

if rdata_offset:
    print(f"\n.rdata section at offset 0x{rdata_offset:X}, VA 0x{rdata_va:X}")

    # Scan for all unicode strings in .rdata
    print("\nAll Unicode strings in .rdata:")
    i = rdata_offset
    while i < rdata_offset + rdata_size - 2:
        s = read_unicode_at_offset(i)
        if s and len(s) >= 3:
            rva = i - rdata_offset + (rdata_va - image_base)
            va = image_base + rva
            print(f"  0x{i:04X} (VA 0x{va:X}): \"{s}\"")
            i += len(s) * 2 + 2
        else:
            i += 2

# Also check .data section
print("\nAll Unicode strings in .data:")
for s in sections:
    if s['name'] == '.data':
        data_offset = s['raw_offset']
        data_size = s['raw_size']
        data_va = image_base + s['va']
        i = data_offset
        while i < data_offset + data_size - 2:
            st = read_unicode_at_offset(i)
            if st and len(st) >= 3:
                rva = i - data_offset + (data_va - image_base)
                va = image_base + rva
                print(f"  0x{i:04X} (VA 0x{va:X}): \"{st}\"")
                i += len(st) * 2 + 2
            else:
                i += 2

# ================================================================
# Look at the INIT section for the actual DriverEntry with IoCreateDevice
# ================================================================
print(f"\n{'=' * 70}")
print("INIT section analysis (DriverEntry and device setup)")
print("=" * 70)

init_sec = None
for s in sections:
    if s['name'] == 'INIT':
        init_sec = s
        break

if init_sec:
    init_offset = init_sec['raw_offset']
    init_size = init_sec['raw_size']
    init_va_base = image_base + init_sec['va']

    init_all = disasm_at(init_va_base, init_size)
    print(f"\nINIT section: VA 0x{init_va_base:X}, size 0x{init_size:X}")
    print(f"Total instructions: {len(init_all)}")

    # The real DriverEntry (0x140001B58) is in .text, but it's called from
    # the GsDriverEntry (0x140006000) which is in INIT
    # Let's check what 0x140001B58 does

# Let's analyze sub_140001B58 which is the real initialization
print(f"\n{'=' * 70}")
print("sub_140001B58 - Real DriverEntry (full)")
print("=" * 70)

real_init = disasm_at(0x140001B58, 0x400)
print(f"\nDisassembly ({len(real_init)} instructions):")

for i, insn in enumerate(real_init):
    if insn.mnemonic == 'ret' and i > 20:
        # Print and stop at return
        print(f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}")
        break
    if insn.mnemonic == 'int3' and i > 5:
        break

    ann = ""
    api = resolve_call(insn)
    if api:
        ann = f"  ; << {api} >>"

    if insn.mnemonic == 'lea':
        ea = resolve_lea(insn)
        if ea:
            ea_off = va_to_offset(ea)
            if ea_off:
                s = read_unicode_at_offset(ea_off)
                if s:
                    ann = f'  ; -> "{s}"'
                else:
                    ann = f"  ; -> VA 0x{ea:X}"

    # Annotate MajorFunction
    if insn.mnemonic == 'mov' and '+' in insn.op_str:
        op = insn.op_str.lower()
        offsets_map = {
            '0x68]': 'DriverUnload',
            '0x70]': 'MajorFunction[IRP_MJ_CREATE]',
            '0x78]': 'MajorFunction[IRP_MJ_CREATE_NAMED_PIPE]',
            '0x80]': 'MajorFunction[IRP_MJ_CLOSE]',
            '0xe0]': 'MajorFunction[IRP_MJ_DEVICE_CONTROL]',
        }
        for off_pattern, label in offsets_map.items():
            if off_pattern in op:
                ann = f"  ; {label}"

    # Immediate value annotations
    if insn.mnemonic == 'mov' and insn.op_str.startswith('r9d') or \
       insn.mnemonic == 'mov' and insn.op_str.startswith('ecx'):
        parts = insn.op_str.split(',')
        if len(parts) == 2:
            try:
                val = int(parts[1].strip(), 16)
                if val == 0x22:
                    ann = "  ; FILE_DEVICE_UNKNOWN"
            except:
                pass

    print(f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}{ann}")

# ================================================================
# Now trace all internal function calls from real DriverEntry
# ================================================================
print(f"\n{'=' * 70}")
print("Internal functions called from DriverEntry")
print("=" * 70)

for insn in real_init:
    if insn.mnemonic == 'ret':
        break
    if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
        target = int(insn.op_str, 16)
        api = resolve_call(insn)
        if not api:
            print(f"\n  Internal call to 0x{target:X} from 0x{insn.address:X}")
            # Disassemble first 30 instructions of target
            sub_insns = disasm_at(target, 0x200)
            for j, si in enumerate(sub_insns[:40]):
                if si.mnemonic == 'int3' and j > 3:
                    break
                sa = ""
                sub_api = resolve_call(si)
                if sub_api:
                    sa = f"  ; << {sub_api} >>"
                if si.mnemonic == 'lea':
                    ea = resolve_lea(si)
                    if ea:
                        ea_off = va_to_offset(ea)
                        if ea_off:
                            s = read_unicode_at_offset(ea_off)
                            if s:
                                sa = f'  ; -> "{s}"'
                print(f"    0x{si.address:X}: {si.mnemonic:8s} {si.op_str}{sa}")

# ================================================================
# Final: Comprehensive IOCTL table with buffer sizes
# ================================================================
print(f"\n{'=' * 70}")
print("COMPREHENSIVE IOCTL TABLE")
print("=" * 70)

# The dispatch handler uses a switch pattern:
# 1. Load IoControlCode
# 2. SUB eax, 0x225348 (base IOCTL)
# 3. If zero -> handle IOCTL 0x225348
# 4. Otherwise CMP against deltas for other IOCTLs
# 5. Second stage: SUB eax, 0x229350 (after adjusting)

# Let's trace the exact switch logic
print("\nIOCTL dispatch logic trace:")
print("  1. Base IOCTL: 0x00225348 (SUB eax, 0x225348)")
print("     - DeviceType=0x22 (FILE_DEVICE_UNKNOWN)")
print("     - Access=READ (0x1)")
print("     - Function=0x4D2")
print("     - Method=BUFFERED (0x0)")
print()
print("  After first SUB, remaining value checked:")
print("  2. SUB 0x229350 appears later -> second branch base")
print("     - This is checked as: original - 0x225348 - delta = 0")
print("     - So delta from base: 0x229350 - 0x225348 = 0x4008")
print("     - IOCTL 0x00229350:")
print("     - DeviceType=0x22, Access=WRITE (0x2), Function=0x4D4, Method=BUFFERED")
print()
print("  3. CMP ecx, 0x229354")
print("     - IOCTL 0x00229354:")
print("     - DeviceType=0x22, Access=WRITE (0x2), Function=0x4D5, Method=BUFFERED")

# Look for additional IOCTLs by scanning for all 0x22XXXX patterns
print("\n\nScanning for ANY immediate values matching IOCTL pattern (0x22XXXX):")
all_text = disasm_at(0x140001000, 0x1200)
ioctl_set = set()
for insn in all_text:
    for part in insn.op_str.split(','):
        part = part.strip()
        if part.startswith('0x'):
            try:
                val = int(part, 16) & 0xFFFFFFFF
                if (val >> 16) == 0x22 and val > 0x220000:
                    ioctl_set.add(val)
                    print(f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str} -> 0x{val:08X}")
            except:
                pass
        # Also check negative/subtracted values
        if part.startswith('-0x'):
            try:
                val = (-int(part, 16)) & 0xFFFFFFFF
                if (val >> 16) == 0x22 and val > 0x220000:
                    ioctl_set.add(val)
                    print(f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str} -> 0x{val:08X}")
            except:
                pass

print(f"\n\nAll unique IOCTL codes found: {len(ioctl_set)}")
for ioctl in sorted(ioctl_set):
    func_code = (ioctl >> 2) & 0xFFF
    access = (ioctl >> 14) & 0x3
    method = ioctl & 0x3
    access_s = {0:'FILE_ANY_ACCESS', 1:'FILE_READ_ACCESS', 2:'FILE_WRITE_ACCESS', 3:'FILE_READ_WRITE_ACCESS'}[access]
    method_s = {0:'METHOD_BUFFERED', 1:'METHOD_IN_DIRECT', 2:'METHOD_OUT_DIRECT', 3:'METHOD_NEITHER'}[method]
    print(f"  0x{ioctl:08X} | Function=0x{func_code:03X} | {access_s:24s} | {method_s}")
