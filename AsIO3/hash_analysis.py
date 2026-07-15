"""
Investigate the hash computation in the driver:
- Function 0x4780 reads the file
- Function 0x48EC appears to be hash init
- Function 0x7450 is the comparison (memcmp 32 bytes)
- Let's look at the hash computation functions

Also: the stored hash might be outdated (driver version doesn't match current AsusCertService)
OR the hash is computed differently (e.g., Authenticode hash, which excludes certain PE fields)
"""
import pefile
import capstone
import struct
import hashlib

DRIVER_PATH = r"C:\\Users\\researcher\\OneDrive\\Desktop\\report\\AsIO3\\Asusgio3.sys"
SERVICE_PATH = r"C:\\Program Files (x86)\\ASUS\\AsusCertService\\AsusCertService.exe"

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
        return
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

# Look at the hash init function 0x48EC
print("="*70)
print("  HASH INIT FUNCTION (0x48EC)")
print("="*70)
disasm_func(0x48EC, 256, "Hash Init (0x48EC)")

# Look at function 0x4780 (file reader / hash update)
disasm_func(0x4780, 512, "File Read + Hash (0x4780)")

# Look at the comparison function 0x7450
disasm_func(0x7450, 128, "Hash Compare (0x7450)")

# Look at the hash update function (called in loop from 0x3324->0x71B0 and 0x335C->0x71F0)
disasm_func(0x71B0, 128, "Hash Update 1 (0x71B0)")
disasm_func(0x71F0, 128, "Hash Update 2 (0x71F0)")

# Now let's look at what comparison is used at 0x3386 (lea rdx, [rip + 0x5DC3])
# 0x14000338D + 0x5DC3 = 0x140009150 -> .data+0x150 (the stored hash!)
# And compare function at 0x7450 takes (rcx=computed, rdx=stored, r8d=0x20=32)
# That's essentially memcmp(computed, stored, 32)

# The key question: what hash algorithm?
# Let's check if it's bcrypt-based (looking for BCrypt* function imports)
print("\n\n" + "="*70)
print("  IMPORTS ANALYSIS - Looking for crypto functions")
print("="*70)
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else f"ord_{imp.ordinal}"
        if any(x in name.lower() for x in ['crypt', 'hash', 'digest', 'md5', 'sha', 'bcrypt']):
            print(f"  {dll}: {name} (IAT VA: 0x{imp.address:X})")

# Check all DLL imports
print("\n  All imported DLLs:")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f"    {entry.dll.decode()}: {len(entry.imports)} imports")

# Maybe the hash is computed inline. Let's look at 0x48EC more carefully
# and see if there are hash constants (SHA-256 initial values, etc.)
print("\n\n" + "="*70)
print("  SEARCHING FOR HASH CONSTANTS IN .rdata")
print("="*70)

# SHA-256 initial hash values (H0-H7)
sha256_h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
# SHA-256 K constants (first few)
sha256_k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5]
# MD5 constants
md5_k = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee]

for section in pe.sections:
    sec_name = section.Name.decode().rstrip('\\x00')
    sec_off = section.PointerToRawData
    sec_size = min(section.Misc_VirtualSize, section.SizeOfRawData)

    # Search for SHA-256 H0
    raw = pe.__data__[sec_off:sec_off+sec_size]
    for i in range(0, len(raw)-4, 4):
        val = struct.unpack_from('<I', raw, i)[0]
        if val == 0x6a09e667:
            print(f"  SHA-256 H0 found in {sec_name} at offset 0x{sec_off+i:X} (section+0x{i:X})")
            # Check if next values match
            if i + 32 <= len(raw):
                vals = [struct.unpack_from('<I', raw, i+j*4)[0] for j in range(8)]
                if vals == sha256_h:
                    print(f"    CONFIRMED: Full SHA-256 initial state at this location!")
        elif val == 0x67e6096a:  # big-endian H0
            print(f"  SHA-256 H0 (BE) found in {sec_name} at offset 0x{sec_off+i:X}")
        elif val == 0x428a2f98:
            print(f"  SHA-256 K[0] found in {sec_name} at offset 0x{sec_off+i:X}")
        elif val == 0xd76aa478:
            print(f"  MD5 K[0] found in {sec_name} at offset 0x{sec_off+i:X}")

# Now try various hashes of AsusCertService.exe to find a match
print("\n\n" + "="*70)
print("  TRYING VARIOUS HASHES OF AsusCertService.exe")
print("="*70)

stored_hash = pe.__data__[0x8350:0x8350+32]
stored_hex = stored_hash.hex().upper()
print(f"  Stored: {stored_hex}")

with open(SERVICE_PATH, 'rb') as f:
    service_data = f.read()

print(f"  File size: {len(service_data)} bytes")

# Full file hashes
tests = {
    "SHA-256 full file": hashlib.sha256(service_data).hexdigest().upper(),
    "MD5 full file": hashlib.md5(service_data).hexdigest().upper(),
    "SHA-1 full file": hashlib.sha1(service_data).hexdigest().upper(),
}

# Try hashing just the PE sections
svc_pe = pefile.PE(SERVICE_PATH)
for sec in svc_pe.sections:
    sec_name = sec.Name.decode().rstrip('\\x00')
    sec_data = service_data[sec.PointerToRawData:sec.PointerToRawData + sec.SizeOfRawData]
    tests[f"SHA-256 section {sec_name}"] = hashlib.sha256(sec_data).hexdigest().upper()

# Try Authenticode hash (excludes checksum and cert table)
# Authenticode hashes the file but excludes:
# - PE checksum (offset 0x58 in OptionalHeader, 4 bytes)
# - Certificate Table directory entry (offset varies)
# - The actual certificate data at the end
pe_offset = struct.unpack_from('<I', service_data, 0x3C)[0]
checksum_off = pe_offset + 0x58  # in optional header
# Certificate table is at Data Directory index 4 (Security)
opt_off = pe_offset + 0x18
magic = struct.unpack_from('<H', service_data, opt_off)[0]
if magic == 0x20B:  # PE32+
    dd_off = opt_off + 0x70  # data directories start
else:
    dd_off = opt_off + 0x60
cert_dir_off = dd_off + 4 * 8  # index 4, each entry 8 bytes
cert_rva = struct.unpack_from('<I', service_data, cert_dir_off)[0]
cert_size = struct.unpack_from('<I', service_data, cert_dir_off + 4)[0]

# Build authenticode hash input
auth_data = bytearray(service_data)
# Zero checksum
auth_data[checksum_off:checksum_off+4] = b'\\x00' * 4
# Zero cert dir entry
auth_data[cert_dir_off:cert_dir_off+8] = b'\\x00' * 8
# Exclude cert data (at end of file)
if cert_rva > 0 and cert_size > 0:
    auth_data = auth_data[:cert_rva]

tests["SHA-256 Authenticode-style"] = hashlib.sha256(bytes(auth_data)).hexdigest().upper()

# Print results
for name, hash_val in tests.items():
    match = "MATCH!" if hash_val[:64] == stored_hex else ""
    # Also check if first 32 chars match (in case it's md5+something)
    print(f"  {name:40s}: {hash_val[:64]} {match}")

# Also try: what if the driver hashes in a different chunk size
# or excludes the PE header?
# Try just the code (.text section) of service
for sec in svc_pe.sections:
    if b'.text' in sec.Name:
        text_data = service_data[sec.PointerToRawData:sec.PointerToRawData + sec.SizeOfRawData]
        h = hashlib.sha256(text_data).hexdigest().upper()
        print(f"  SHA-256 .text only ({len(text_data)} bytes): {h}")

# Try concatenated MD5+MD5 (32 bytes = two 16-byte hashes?)
md5_full = hashlib.md5(service_data).digest()
# First 16 bytes + last 16 bytes of sha256?
sha = hashlib.sha256(service_data).digest()
print(f"  MD5: {md5_full.hex().upper()}")
print(f"  SHA256[:16]+SHA256[16:]: {sha.hex().upper()}")
print(f"  MD5+MD5(reversed): {(md5_full + md5_full[::-1]).hex().upper()}")

# Maybe it's the hash of a SUBSECTION of the file
# The enrollment code reads 0x3F bytes at a time (from loop at 0x330A: lea ebx, [rdi + 0x3f])
# Actually that's the buffer size for reading. Let me check.

print("\\n\\nDONE")
