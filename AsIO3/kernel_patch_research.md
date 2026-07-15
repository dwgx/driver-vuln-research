# AsIO3 Kernel Patch Research via SIVX64 (v2)

Date: 2026-07-11 19:31:21
Method: SIVX64 phys R/W -> CR3 discovery -> page table walk -> .data patch

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| BSOD | Immediate crash on bad write | Read-first verification |
| PatchGuard | .text mods detected in 5-10min | Only patching .data (SAFE) |
| Driver corruption | Requires reboot | Only modifying counters/tables |
| EAC detection | Potential ban | AsIO3 is not EAC-monitored |

## Strategy

**Target: .data section only (PatchGuard-safe)**

1. Zero denylist count at RVA 0x95C0 (disables Phase 3 RAM denylist)
2. Patch static allowlist at RVA 0x9130 to cover all physical memory
3. Result: AsIO3 allows mapping ANY physical address

## Findings

### AsIO3 Module

- **Name**: `AsIO3.sys`
- **Base**: `0xFFFFF80612850000`

### CR3

FAILED

## Execution Log

```
[19:31:20.188] [INFO] Step 1: SIVX64 driver setup...
[19:31:20.981] [INFO] SIVDRIVER device opened
[19:31:20.981] [INFO] SIVX64 working (APIC read: ffffffff)
[19:31:20.981] [INFO] 
Step 2: Locating AsIO3.sys in kernel...
[19:31:20.992] [INFO] AsIO3: AsIO3.sys @ 0xFFFFF80612850000
[19:31:20.992] [INFO] 
Step 3: Discovering System CR3...
[19:31:20.992] [INFO] Strategy 1: KPCR via MSR 0xC0000102 (IA32_KERNEL_GS_BASE)...
[19:31:20.992] [WARN]   KERNEL_GS_BASE read failed or invalid: 590753247232
[19:31:20.992] [INFO]   ntoskrnl base = 0xFFFFF8067D600000
[19:31:20.992] [INFO]   Kernel PML4 index = 496 (0x1F0)
[19:31:20.993] [INFO] Strategy 2: PML4 scan for System CR3...
[19:31:21.005] [INFO]   Not found in first 16MB. Scanning 16MB-256MB...
[19:31:21.201] [INFO] Strategy 3: Try ANY valid CR3 for kernel-space reads...
[19:31:21.262] [ERR] All CR3 discovery strategies FAILED
[19:31:21.262] [ERR] CR3 discovery FAILED
```