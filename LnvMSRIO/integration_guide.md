# LnvMSRIO Integration Guide for saomola-tui

## Overview

LnvMSRIO.sys (CVE-2025-8061) is the preferred physical memory driver for saomola-tui.
It provides unrestricted MmMapIoSpace-based physical memory read/write through a simple
16-byte IOCTL interface. It operates while EAC is active with no observed bans.

---

## Prerequisites

1. **Driver file**: `LnvMSRIO.sys` (SHA256: `245b6ab442a7d53dc30ece28e1c6de727c019669385877cbe929b81aa1a2ad2f`)
   - Place in a stable path, e.g. `drivers/LnvMSRIO.sys`
   - 50,216 bytes, Lenovo-signed, x86-64

2. **Administrator rights**: Required for `sc create` / `sc start` and device handle opening

3. **No HVCI/VBS**: MmMapIoSpace may be blocked on systems with Hypervisor-enforced Code Integrity

4. **Windows 10/11 x64**: Tested on Win11 25H2 Build 26200

---

## Loading Procedure

### Service Creation and Start

```cmd
sc create LnvMSRIO type= kernel binPath= "C:\absolute\path\to\LnvMSRIO.sys"
sc start LnvMSRIO
```

Use a fixed service name (`LnvMSRIO`) for easy cleanup after crashes.

### Verify Load

Open device handle to `\\.\WinMsrDev`. Send IOCTL `0x9C402000` (Get Version).
Expected return: 4 bytes containing `0x01000000`.

### Rust Code (from lnvmsrio_backend.rs)

```rust
let driver = LnvMsrioDriver::open()?;  // Opens \\.\WinMsrDev
assert!(driver.probe());                 // Sends version IOCTL
```

---

## IOCTL Usage for Physical Memory Read

### Read Operation

- IOCTL code: `0x9C406104`
- Method: `METHOD_BUFFERED`
- Input: 16 bytes (`PhysMemReadInput`)
- Output: `access_size * count` bytes

```rust
#[repr(C, packed)]
struct PhysMemReadInput {
    physical_address: u64,  // +0x00: target physical address
    access_size: u32,       // +0x08: 1=BYTE, 2=WORD, 8=QWORD
    count: u32,             // +0x0C: number of elements
}
```

For arbitrary-length reads, use `access_size = 1` and `count = byte_length`.

### Write Operation

- IOCTL code: `0x9C40A108`
- Method: `METHOD_BUFFERED`
- Input: 16-byte header + data payload

```rust
#[repr(C, packed)]
struct PhysMemWriteHeader {
    physical_address: u64,  // +0x00
    access_size: u32,       // +0x08
    count: u32,             // +0x0C
    // data follows at +0x10
}
```

### Internal Mechanism

The driver calls `MmMapIoSpace(PhysicalAddress, total_size, MmNonCached)`, copies
data to/from the mapped region, then calls `MmUnmapIoSpace`. No address validation
is performed by the driver itself.

---

## Safety Constraints (MANDATORY)

The driver performs NO address validation. All safety checks must be in userspace code.

### Verified Safe Physical Address Ranges (firmware-confirmed, 3 methods cross-validated)

```
Range 1: 0x001000 - 0x09F000       (0.6 MB, low conventional memory)
Range 2: 0x100000 - 0x581EE000     (1.38 GB, main below-4GB RAM)
Range 3: 0x63FFF000 - 0x64000000   (4 KB, boundary page)
Range 4: 0x100000000 - 0x880000000 (30 GB, above-4GB RAM)
```

### Dangerous Zones (reads will BSoD or hang)

```
0x0 - 0x1000              NULL page
0x9F000 - 0x100000        BIOS/VGA ROM (384 KB)
0x581EE000 - 0x63FFF000   ACPI NVS + UEFI runtime (190 MB)
0x64000000 - 0x100000000  PCI MMIO hole (2.44 GB, includes GPU BAR)
0x880000000+              Beyond physical RAM
```

### Rust Validation Function

```rust
fn is_safe_phys_addr(addr: u64) -> bool {
    (addr >= 0x1000 && addr < 0x9F000) ||
    (addr >= 0x100000 && addr < 0x581EE000) ||
    (addr >= 0x63FFF000 && addr < 0x64000000) ||
    (addr >= 0x100000000 && addr < 0x880000000)
}
```

Every physical address MUST pass this check before being sent to the driver.

### Hard Limits

- Maximum 100 IOCTL calls per script execution (global counter)
- NEVER do page table walks for user-mode addresses (5 BSoDs confirmed this is impossible)
- NEVER write to physical memory without explicit user confirmation
- Only use Superfetch-confirmed addresses or kernel_vtop.bin mapped addresses for reads

---

## Cleanup Procedure

```cmd
sc stop LnvMSRIO
sc delete LnvMSRIO
```

Always clean up after use. The fixed service name `LnvMSRIO` ensures manual cleanup
is possible if the process crashes.

### In Rust

```rust
impl Drop for LnvMsrioDriver {
    fn drop(&mut self) {
        // CloseHandle on device
    }
}
// Then separately:
// std::process::Command::new("sc").args(["stop", "LnvMSRIO"]).output();
// std::process::Command::new("sc").args(["delete", "LnvMSRIO"]).output();
```

---

## Why LnvMSRIO over SIVX64 / ASMMAP64

| Factor | LnvMSRIO | SIVX64 | ASMMAP64 |
|--------|----------|--------|----------|
| Works with EAC active | YES (confirmed) | Unknown | Unknown |
| No ban observed | 72h+ clean | Not tested | Not tested |
| Range restrictions | NONE | NONE | NONE |
| MSR access | YES | NO | NO |
| IO port access | YES | NO | NO |
| PCI config | YES | NO | NO |
| Access control | NONE | NONE | NONE |
| Signature | Lenovo (trusted vendor) | SIV (hw monitor) | ASRock (mobo) |
| Detection risk | LOW (utility driver) | MEDIUM | MEDIUM |

### Key Advantages

1. **EAC coexistence**: Confirmed working while EAC is active. No ban in 72h observation.
2. **Broadest capability set**: Single driver covers phys mem, MSR, IO, PCI.
3. **Lenovo signature**: Less suspicious than hardware monitor drivers in AV heuristics.
4. **No range limits**: Unlike AsIO3 which has `g_goodRanges` whitelist.
5. **Simple interface**: 16-byte fixed-size input for reads, no complex handshakes.

---

## Integration Point in saomola-tui

In `driver_chain.rs`, LnvMSRIO should be priority 0 (highest):

```
Driver chain priority: LnvMSRIO (0) > AsIO3 (1) > ASMMAP64 (2) > SIVX64 (3)
```

The `LnvMsrioInfo::CHAIN_PRIORITY` constant is already set to 0 in the backend.

Device path: `\\.\WinMsrDev`
Service name: `LnvMSRIO`

---

## Usage in toolkit Pipeline

1. **PPL bypass**: Write 0x00 to EPROCESS +0x87A via `write_physical_memory`
2. **EPROCESS scan**: Walk ActiveProcessLinks at +0x540, read PID at +0x1D0
3. **Kernel address reads**: Use kernel_vtop.bin for VA-to-PA, then read via IOCTL
4. **AES key scan**: Read Superfetch-confirmed physical pages, pattern match for keys

User-mode memory reads via page table walks are FORBIDDEN (5 BSoDs). Only
Superfetch PfnQuery or pre-built kernel_vtop.bin mappings are acceptable sources
for physical addresses.
