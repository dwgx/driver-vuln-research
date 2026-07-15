"""
DEFINITIVE ANALYSIS of AsIO3 whitelist mechanism.

KEY DISCOVERIES:
1. Function 0x340C is the IRP_MJ_CREATE access check
2. It calls 0x197C which uses ZwQueryInformationProcess to get caller's image path
3. Then it iterates the QWORD array at .data+0x3C0 comparing the QWORD value
4. Wait - the comparison at 0x343A is: cmp qword ptr [rax], rdx
   where rdx = qword ptr [rsp+0x30] = result from 0x197C
   This means 0x197C returns a QWORD value, not a PID!

Let's figure out what 0x197C actually returns.
0x197C resolves ZwQueryInformationProcess, calls it with:
  - ProcessHandle = -1 (current process)
  - InformationClass = 0x2B (ProcessImageFileName)
  - ReturnLength stored, then allocates buffer, calls again
  - Returns: [rsp+0x60] = the process ID? No...

Actually wait - let me re-read 0x197C:
  0x1400019C1: xor r9d, r9d       ; ReturnLength ptr = 0 initially
  0x1400019D2: xor edx, edx       ; InformationClass = 0 !!!
  0x1400019D4: or rcx, -1         ; ProcessHandle = NtCurrentProcess()
  0x1400019D8: call [ZwQueryInformationProcess]  r9d=0x30, r8=[rsp+0x40]

Wait, that's wrong. Let me look again:
  r9d = 0x30 (InformationLength)
  r8 = [rsp+0x40] (Buffer)
  edx = 0 (InformationClass = ProcessBasicInformation!)
  rcx = -1 (NtCurrentProcess)

ProcessBasicInformation (class 0) returns a PROCESS_BASIC_INFORMATION struct.
The result at [rsp+0x60] offset within the 0x30 buffer...
Wait: buffer at [rsp+0x40], size 0x30
  PROCESS_BASIC_INFORMATION:
    +0x00: ExitStatus (4/8)
    +0x08: PebBaseAddress (8)
    +0x10: AffinityMask (8)
    +0x18: BasePriority (4/8)
    +0x20: UniqueProcessId (8)
    +0x28: InheritedFromUniqueProcessId (8)

[rsp+0x60] = buffer_start + 0x20 = UniqueProcessId!

So 0x197C returns THE CALLER'S PID. That's what goes into [rsp+0x30] in 0x340C.
Then 0x340C compares this PID as a QWORD against the .data+0x3C0 array.

But wait - the values in the array are NOT simple PIDs!
They have patterns like hi=0x000013D4 lo=0x0000130C

UNLESS... these are initialized with actual running PIDs at runtime.
The on-disk .data values we're reading are just whatever was in memory
when the file was saved/copied from a RUNNING system.

So the .data section we're reading has STALE runtime PIDs from when the driver
was captured. ON DISK the initial values would all be 0.
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

def disasm_func(rva, max_size=512, label=""):
    offset = rva_to_offset(rva)
    if offset is None:
        return []
    raw = pe.__data__[offset:offset+max_size]
    instructions = list(md.disasm(raw, IMAGE_BASE + rva))
    print(f"\n{'='*70}")
    print(f"  {label} (RVA 0x{rva:X})")
    print(f"{'='*70}")
    for ins in instructions:
        print(f"  0x{ins.address:X}:  {ins.mnemonic:<10} {ins.op_str}")
        if ins.mnemonic == 'ret':
            break
        if ins.mnemonic == 'int3':
            break
    return instructions

# ============================================================
# Now let's figure out the ENROLLMENT function (called 0x3100 area)
# The big function that adds PIDs to the whitelist.
# We know it:
#   1. Calls ZwQueryInformationProcess (0x197C) to get current process PID
#   2. Compares path against "C:\Program Files (x86)\ASUS\AsusCertService"
#   3. Has a secondary check via function 0x130C
#   4. Adds PID to the QWORD array
#
# The critical question: WHERE is this enrollment function CALLED FROM?
# It's NOT the process notify callback (which only handles exit).
# It must be called from IRP_MJ_CREATE itself!
# ============================================================

print("="*70)
print("  ANALYSIS: HOW IRP_MJ_CREATE DECIDES ACCESS")
print("="*70)
print("""
The dispatch table setup shows:
  DRIVER_OBJECT+0x70 = MajorFunction[IRP_MJ_CREATE] = RVA 0x1A00
  DRIVER_OBJECT+0x80 = MajorFunction[IRP_MJ_CLOSE] = RVA 0x1A00 (same!)
  DRIVER_OBJECT+0xE0 = MajorFunction[IRP_MJ_DEVICE_CONTROL] = RVA 0x1A00 (same!)
  DRIVER_OBJECT+0x68 = MajorFunction[IRP_MJ_CLEANUP?] = RVA 0x2CB0

Wait - ALL dispatch goes to 0x1A00? That's the shared handler!
It checks the MajorFunction code at IO_STACK_LOCATION:
  - [r10] = MajorFunction byte
  - al == 0 (IRP_MJ_CREATE) -> jump to 0x2777
  - al == 2 (IRP_MJ_CLOSE) -> jump to 0x276D
  - al == 0xE (IRP_MJ_DEVICE_CONTROL) -> IOCTL dispatch

So IRP_MJ_CREATE handler is at RVA 0x2777!
""")

disasm_func(0x2777, 256, "IRP_MJ_CREATE (MajorFunction==0, at RVA 0x2777)")

# ============================================================
# Also look at IRP_MJ_CLOSE (al==2)
# ============================================================
disasm_func(0x276D, 64, "IRP_MJ_CLOSE (MajorFunction==2, at RVA 0x276D)")

# ============================================================
# Now the KEY question: What is at the address referred by
# 0x14000342E: lea rax, [rip + 0x5F8B]
# = 0x140003435 + 0x5F8B = 0x1400093C0
# That's .data+0x3C0! The QWORD PID array!
#
# And the end: 0x140003443: lea r8, [rip + 0x6176]
# = 0x14000344A + 0x6176 = 0x1400095C0
# That's .data+0x5C0! End of the 64-QWORD array (0x3C0 + 64*8 = 0x3C0+0x200 = 0x5C0)
# ============================================================
print("\n\n" + "="*70)
print("  CONFIRMING: IRP_MJ_CREATE PID CHECK at 0x340C")
print("="*70)
print("""
  0x340C: sub rsp, 0x28
  0x3410: and qword ptr [rsp+0x30], 0     ; zero local var
  0x3416: lea rcx, [rsp+0x30]             ; ptr to receive PID
  0x341B: call 0x197C                      ; get current process PID
  0x3420: test eax, eax                    ; success?
  0x3422: jns 0x3429                       ; if ok, continue
  0x3424: lfence                           ; memory fence (spectre?)
  0x3427: jmp 0x3455                       ; return (eax = status)
  0x3429: mov rdx, [rsp+0x30]             ; rdx = our PID
  0x342E: lea rax, [rip+0x5F8B]           ; rax = &whitelist[0] (.data+0x3C0)
  0x3435: mov ecx, 0xC0000001             ; default = STATUS_UNSUCCESSFUL
  0x343A: cmp [rax], rdx                  ; compare whitelist entry to our PID
  0x343D: je 0x3451                        ; MATCH! -> success
  0x343F: add rax, 8                       ; next entry
  0x3443: lea r8, [rip+0x6176]            ; r8 = &whitelist[64] (.data+0x5C0)
  0x344A: cmp rax, r8                     ; end of array?
  0x344D: jl 0x343A                        ; loop
  0x344F: jmp 0x3453                       ; no match -> fail
  0x3451: xor ecx, ecx                    ; STATUS_SUCCESS
  0x3453: mov eax, ecx                    ; return status
  0x3455: add rsp, 0x28
  0x3459: ret

  CONCLUSION: The IRP_MJ_CREATE handler calls 0x340C.
  0x340C gets the CURRENT process PID via ZwQueryInformationProcess,
  then linearly scans the 64-QWORD array at .data+0x3C0.
  If PID is found -> return 0 (success).
  If not found -> return 0xC0000001 (STATUS_UNSUCCESSFUL).

  The Security Descriptor is checked FIRST by the I/O manager before
  the IRP even reaches the driver. If that passes, the driver's
  IRP_MJ_CREATE then does this PID check.
""")

# ============================================================
# Now: WHERE does the enrollment happen?
# The enrollment function is at ~0x3100. Let's find who calls it.
# Actually, let me look at function 0x3100 start more carefully.
# ============================================================
print("\n\n" + "="*70)
print("  ENROLLMENT FUNCTION (starting at ~0x3138)")
print("  This is where PIDs get ADDED to the whitelist")
print("="*70)

# The function appears to start at the int3 boundary before 0x3138
# Actually from the disasm: 0x14000313C starts with garbage (misaligned)
# The real start is at 0x140003138 or nearby. Let me find it.
# Looking at the code at 0x3146: push r14, push r15, sub rsp, 0x140
# That looks like a function prologue. Let me check one byte before.

# From the earlier output, there's:
#   0x14000313F: je 0x140003165
#   0x140003141: ...
# This looks like misaligned disassembly. The real function start must be
# at an int3 boundary. Let me look just before 0x3138.

offset_3130 = rva_to_offset(0x3130)
raw_bytes = pe.__data__[offset_3130:offset_3130+16]
print(f"  Bytes at RVA 0x3130: {' '.join(f'{b:02X}' for b in raw_bytes)}")

# Actually, from the PsGetProcessImageFileName call search, let me find
# where PsGetProcessImageFileName is imported and called
print("\n\n" + "="*70)
print("  FINDING PsSetCreateProcessNotifyRoutineEx REGISTRATION")
print("="*70)

# The notify callback is registered in DriverEntry. Let's find the call.
# From init function at 0x16C4:
# 0x14000184E: lea rcx, [rip + 0x247B]
# = 0x140001855 + 0x247B = 0x140003CD0  <-- That's our callback!
# 0x140001855: call [rip + 0x68E5]     <-- PsSetCreateProcessNotifyRoutineEx

print("""
  From init at 0x16C4:
  0x14000184C: xor edx, edx                    ; Remove = FALSE (register)
  0x14000184E: lea rcx, [rip + 0x247B]         ; rcx = 0x140003CD0 (callback)
  0x140001855: call [PsSetCreateProcessNotifyRoutineEx]

  So the callback at 0x3CD0 IS registered. But we showed it only handles EXIT.
  When r8 (CreateInfo) != NULL, it just returns immediately.

  THIS MEANS: The driver does NOT enroll PIDs via process creation notification!

  The enrollment must happen DIFFERENTLY. Let me look at IRP_MJ_CREATE flow.
""")

# ============================================================
# Let's look at what happens at RVA 0x2777 (IRP_MJ_CREATE target)
# ============================================================
disasm_func(0x2777, 256, "IRP_MJ_CREATE flow at 0x2777")

# Let me also look at the IOCTL dispatch entry point and PID check there
print("\n\n" + "="*70)
print("  IOCTL DISPATCH - PID CHECK BEFORE IOCTL HANDLING")
print("="*70)
print("""
  From earlier analysis, the IOCTL dispatch (al==0xE) at 0x1A7E:
  0x140001B44: call 0x14000143C   ; This is called before IOCTL handling

  But 0x143C is the IOCTL CODE range check, not PID check!
  Let me look at what 0x14BC does (previously identified as PID check)
""")

disasm_func(0x14BC, 128, "Function 0x14BC (the ACTUAL PID whitelist check for IOCTLs)")

# Let's also look at function 0x1514 (range validation)
disasm_func(0x1514, 256, "Function 0x1514 (range validation)")

# ============================================================
# CRUCIAL: The enrollment function at ~0x3138
# This is a PAGE section function that gets called by the driver
# Let me look for calls to 0x3138 or the real start
# ============================================================
print("\n\n" + "="*70)
print("  FINDING THE ENROLLMENT FUNCTION ENTRY POINT")
print("="*70)

# Let me look for function boundaries (int3 padding) near 0x3100
for test_rva in range(0x3100, 0x3150):
    test_off = rva_to_offset(test_rva)
    if test_off:
        b = pe.__data__[test_off]
        if b == 0xCC:  # int3
            # Check if next byte is NOT int3 (function start)
            next_b = pe.__data__[test_off + 1]
            if next_b != 0xCC:
                print(f"  Function boundary: int3 at RVA 0x{test_rva:X}, function starts at 0x{test_rva+1:X}")
                print(f"  First bytes: {' '.join(f'{pe.__data__[test_off+1+i]:02X}' for i in range(8))}")

# The function that references the path string at 0x32AB (lea rdx, [rip+0x4A6E] -> 0x7D20)
# This is INSIDE a function. Let me find that function's start by looking backwards
print("\n  Looking backwards from 0x32AB for function prologue...")
for search_rva in range(0x3100, 0x3140):
    off = rva_to_offset(search_rva)
    if off:
        # Common function prologues
        bytes_here = pe.__data__[off:off+4]
        # Check for: push rbx = 0x53, push rbp = 0x55, sub rsp = 48 83 EC
        # Or: mov [rsp+X], rbx = 48 89 5C 24
        if bytes_here[:4] == b'\x48\x89\x5c\x24' or bytes_here[:2] == b'\x48\x83':
            # Verify there's int3 or ret just before
            if off > 0:
                prev = pe.__data__[off-1]
                if prev == 0xCC or prev == 0xC3:
                    print(f"  FOUND: Function start at RVA 0x{search_rva:X}")
                    print(f"  Bytes: {' '.join(f'{pe.__data__[off+i]:02X}' for i in range(16))}")
                    disasm_func(search_rva, 1024, f"Enrollment Function (RVA 0x{search_rva:X})")
                    break

print("\n\nDONE")
