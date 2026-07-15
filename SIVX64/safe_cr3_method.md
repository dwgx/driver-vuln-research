# Safe CR3 Discovery via KPCR Method (SIVX64.sys)

## Why Brute-Force Scanning Crashes the System

The naive approach scans physical memory page-by-page (0x0000 to 256MB in 4KB
steps) looking for EPROCESS signatures. This causes crashes for several reasons:

1. **MMIO regions**: Physical address space includes memory-mapped I/O for
   hardware devices (GPU VRAM, PCIe BARs, ACPI tables). Reading from these
   regions can trigger side effects — GPU state corruption, DMA controller
   resets, or NMI watchdog timeouts.

2. **Volume**: A 256MB scan at 4KB granularity = 65,536 IOCTL calls. Each IOCTL
   transitions from usermode → kernel → driver → physical read → back. At this
   volume, timing-sensitive kernel structures (scheduler, DPC queues) can be
   disrupted by the constant interrupts.

3. **Race conditions**: The kernel actively remaps physical pages. A page valid
   at scan time T may be reclaimed by T+1ms. Reading freed/reassigned pages can
   return garbage that looks like a valid EPROCESS, leading to wrong CR3 values
   that cause page faults when used.

4. **Anti-cheat detection**: High-frequency IOCTL patterns are trivially
   detectable by kernel-mode anti-cheat (EAC). 65K+ calls in seconds is a
   bright red flag.

---

## The Correct 5-Step KPCR Method

### Overview

Instead of scanning, we use the CPU's own architectural registers to navigate
directly to kernel structures. Total physical reads: 5-15 (vs 65,536+).

### Step 1: Get ntoskrnl.exe Base Address (0 IOCTLs)

```
NtQuerySystemInformation(SystemModuleInformation = 11)
→ First module entry → ImageBase field at offset +0x10
```

This is a documented usermode NTAPI. No driver interaction needed. Returns the
virtual address where ntoskrnl.exe is loaded (e.g., `0xFFFFF80234200000`).

**Purpose**: We need a known kernel VA to verify CR3 candidates — if a CR3
correctly translates this VA to a physical page containing "MZ", it's valid.

### Step 2: RDMSR → KPCR Virtual Address (1 IOCTL)

```
SIVX64 IOCTL 0x08: Read MSR 0xC0000102 (IA32_KERNEL_GS_BASE)
→ Returns KPCR virtual address for CPU 0
```

On Windows x64, the GS segment base in kernel mode points to the per-processor
KPCR (_KPCR) structure. When executing in usermode, the kernel GS base is stored
in MSR 0xC0000102 (swapped via SWAPGS on syscall entry).

**Output**: A kernel-space VA like `0xFFFFF802345B7000` (the KPCR).

### Step 3: Verify CR3 via Known Candidates (3-5 IOCTLs per attempt)

The System process (PID 4) CR3 is allocated very early during boot and lands in
a predictable range of physical addresses. Common values on Windows 11:

```
0x001AD000  (most common, Win11 23H2/25H2)
0x001AA000  (common variant)
0x006D4000, 0x006E4000  (some builds)
0x001A0000, 0x00190000, 0x001B0000  (variants)
```

For each candidate CR3, we perform a 4-level page table walk on `kernel_base`:

```
CR3 → PML4E → PDPTE → PDE → PTE → physical_addr
Read 4 bytes at physical_addr → check for "MZ"
```

This is 4 reads (page walk) + 1 read (MZ verify) = 5 reads per attempt.
In practice, the first or second candidate works.

### Step 4: KPCR → CurrentThread → Process → CR3 (3 virtual reads)

With a working CR3, we can now read kernel virtual memory:

```
KPCR + 0x180 = KPRCB (embedded, not a pointer)
KPRCB + 0x008 = CurrentThread (KTHREAD*)
KTHREAD + 0x220 = Process (EPROCESS*)
EPROCESS + 0x028 = DirectoryTableBase (CR3)
EPROCESS + 0x440 = UniqueProcessId (verify = 4)
```

If CurrentThread belongs to the System process (common on CPU 0), we get the
CR3 directly. Otherwise, walk ActiveProcessLinks at EPROCESS+0x448 to find
PID 4.

### Step 5: Final Verification (1 read)

Re-verify the discovered System CR3 by translating `kernel_base` and reading
the MZ header. This confirms the CR3 is not stale.

---

## Windows 11 Build 26200 (25H2) Offsets

All offsets verified via WinDbg `dt nt!_STRUCTURE` on Build 26200:

### KPCR (_KPCR)
| Field | Offset | Notes |
|-------|--------|-------|
| Prcb (KPRCB) | +0x180 | Embedded structure, not a pointer |

### KPRCB (_KPRCB, embedded at KPCR+0x180)
| Field | Offset from KPRCB | Offset from KPCR |
|-------|-------------------|-----------------|
| CurrentThread | +0x008 | +0x188 |

### KTHREAD (_KTHREAD)
| Field | Offset | Notes |
|-------|--------|-------|
| Process | +0x220 | Pointer to owning EPROCESS |

### EPROCESS (_EPROCESS)
| Field | Offset | Notes |
|-------|--------|-------|
| DirectoryTableBase | +0x028 | Page table root (CR3) |
| UniqueProcessId | +0x440 | PID |
| ActiveProcessLinks | +0x448 | LIST_ENTRY (doubly-linked) |
| ImageFileName | +0x5A8 | char[15], null-terminated |

### MSR Registers
| MSR | Index | Content |
|-----|-------|---------|
| IA32_GS_BASE | 0xC0000101 | Current GS base (kernel KPCR when in ring 0) |
| IA32_KERNEL_GS_BASE | 0xC0000102 | Swap target (kernel KPCR when in ring 3) |

### SIVX64.sys IOCTL Codes
| Function | Code | Input | Output |
|----------|------|-------|--------|
| RDMSR | 0x08 | u32 msr_index | u64 value |
| PhysMem Read (scatter) | 0x10 | u64 addr + u32 size | raw bytes |
| PhysMem Read (bulk) | 0x13 | u64 addr + u32 size | raw bytes |

---

## How to Verify the CR3 is Correct

A valid System CR3 must satisfy ALL of these checks:

1. **Page-aligned**: `CR3 & 0xFFF == 0` (low 12 bits must be zero)
2. **Non-zero**: `CR3 != 0`
3. **Reasonable range**: `CR3 < 0x800000000` (under 32GB — System is allocated early)
4. **MZ test**: Translating `ntoskrnl_base` through the page tables rooted at
   this CR3 must yield a physical page starting with `4D 5A` ("MZ")
5. **Self-consistent**: Reading `EPROCESS.DirectoryTableBase` for the process
   found via the KPCR chain should equal (or be close to) the CR3 we verified

The MZ test is the strongest verification — it proves the page table walk
produces a meaningful result for a known kernel VA.

---

## Maximum Number of IOCTL Calls

### Best case (first CR3 candidate works, current thread is System):
```
Step 2: 1 RDMSR
Step 3: 4 reads (page walk) + 1 read (MZ) = 5
Step 4: 3 virtual reads × ~3 reads each (with 2MB pages) = 9
Step 5: 4 reads (page walk) + 1 read (MZ) = 5
Total: 1 + 5 + 9 + 5 = 20 IOCTLs
```

### Typical case (2nd candidate, current thread is System):
```
Step 2: 1 RDMSR
Step 3: 5 (failed) + 5 (success) = 10
Step 4: 9
Step 5: 5
Total: 1 + 10 + 9 + 5 = 25 IOCTLs
```

### Worst case (5 candidates tried, process list walk needed):
```
Step 2: 1 RDMSR
Step 3: 5 × 5 = 25 (5 failed candidates)
Step 4: 9 + ~30 (walk 10 processes × 3 reads each)
Step 5: 5
Total: 1 + 25 + 39 + 5 = 70 IOCTLs
```

### Comparison with brute force:
```
Brute force 256MB: 65,536 IOCTLs minimum
KPCR method:       15-70 IOCTLs (typically ~20)
Reduction:         ~1000x fewer driver calls
```

---

## Safety Guarantees

1. **No writes**: Only RDMSR and physical memory READ operations. Never writes.
2. **No MMIO risk**: All accessed physical addresses are in known RAM ranges
   (low memory for page tables, kernel image region for MZ verify).
3. **Bounded iteration**: Process list walk capped at 500 steps with cycle detection.
4. **Fail-safe**: Every pointer read is validated (kernel-space check ≥ 0xFFFF800000000000,
   page-alignment check for CR3 values, present-bit check for page table entries).
5. **No timing dependency**: Reads kernel structures that are stable (page tables,
   EPROCESS, KPCR) — not transient buffers or lock-protected data.

---

## Usage

```bash
# System CR3 only (driver already loaded):
python safe_cr3_finder.py

# Auto-load driver + find System CR3:
python safe_cr3_finder.py --driver D:\Project\toolkit\drivers\Vulnerable-Monitors\SIVX64.sys

# Find VRChat process CR3:
python safe_cr3_finder.py --driver path\to\SIVX64.sys --pid 12345

# JSON output for integration with saomola-tui:
python safe_cr3_finder.py --json --pid 12345
```
