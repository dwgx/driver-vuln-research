# SIVX64.sys MSR Protocol Reference

## Overview

SIVX64.sys provides direct RDMSR/WRMSR access via IOCTLs 0x08 and 0x0C.
WRMSR has a whitelist; RDMSR has a blacklist of one MSR.

**Device Path:** `\\.\SIVDRIVER`  
**No authentication or privilege check beyond initial device open (requires admin).**

---

## IOCTL 0x08 — RDMSR (Read Model-Specific Register)

**Handler VA:** 0x225F2 (PAGE section, file offset 0xF3F2)

### Input Buffer

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | MSR_Index | ECX value for RDMSR instruction |

**InputBufferLength:** minimum 4 bytes.

### Output Buffer

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 8 | MSR_Value | Full 64-bit MSR value (EDX:EAX combined) |

**OutputBufferLength:** minimum 8 bytes.

### Validation

1. **InputBufferLength >= 4:** `cmp ebx, 4; jb fail`
2. **OutputBufferLength >= 8:** `cmp r13d, 8; jb fail`
3. **Blacklist check (2 entries):**
   - MSR 0xC0010117 (AMD IBS_DC_PHYS_ADDR) → rejected with STATUS_ILLEGAL_INSTRUCTION
   - MSR 0x00000000 (null) → rejected with STATUS_ILLEGAL_INSTRUCTION

### Special Handling

- **MSR 0x8B (IA32_BIOS_SIGN_ID):** Before reading, executes `CPUID(EAX=1)` first. This is standard practice because the microcode signature MSR requires CPUID to update its value.

### Operation

```asm
mov ecx, [input_msr_index]     ; Load MSR number
rdmsr                           ; Execute RDMSR (result in EDX:EAX)
shl rdx, 0x20                   ; Shift EDX to upper 32 bits
or  rax, rdx                    ; Combine into 64-bit value
mov [output_buffer], rax        ; Store to output
```

### Return Values

| Status | Meaning |
|--------|---------|
| STATUS_SUCCESS (0) | MSR read successful, IoStatus.Information = 8 |
| 0xC000001D | STATUS_ILLEGAL_INSTRUCTION — blacklisted MSR |

### Error Handling

- **No __try/__except around RDMSR!** If an invalid/non-existent MSR is read, this will cause a #GP fault → BSOD (KeBugCheckEx)
- The blacklist only prevents 2 specific MSRs
- All other MSRs are readable without restriction

### Useful MSRs for Physical Memory Operations

| MSR | Name | Value |
|-----|------|-------|
| 0xC0000082 | IA32_LSTAR | KiSystemCall64 address → kernel base |
| 0xC0000101 | IA32_GS_BASE | Current thread KPCR |
| 0xC0000102 | IA32_KERNEL_GS_BASE | Swapped GS base (user GS from kernel) |
| 0x1B | IA32_APIC_BASE | APIC physical base address |
| 0x176 | IA32_SYSENTER_EIP | Legacy syscall entry |
| 0x48 | IA32_SPEC_CTRL | Speculation control (Spectre mitigations) |

---

## IOCTL 0x0C — WRMSR (Write Model-Specific Register)

**Handler VA:** 0x224A8 (PAGE section, file offset 0xF2A8)

### Input Buffer

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | MSR_Index | ECX value for WRMSR |
| 0x04 | 4 | Value_Low | EAX value (lower 32 bits) |
| 0x08 | 4 | Value_High | EDX value (upper 32 bits) |

**InputBufferLength:** minimum 12 (0x0C) bytes.

### Output Buffer

Same as input (echoed back). OutputBufferLength >= 12.

### Validation

1. **InputBufferLength >= 0x0C:** `cmp ebx, 0xc; jb fail`
2. **OutputBufferLength >= 0x0C:** `cmp r13d, 0xc; jb fail`
3. **Whitelist check (6 entries):**

### WRMSR Whitelist

| MSR | Name | Purpose |
|-----|------|---------|
| 0x38D | IA32_FIXED_CTR_CTRL | Fixed performance counter control |
| 0x38F | IA32_PERF_GLOBAL_CTRL | Global performance counter enable |
| 0x19C | IA32_THERM_STATUS | Thermal status (RO on modern CPUs but writable bit to clear) |
| 0x110A | Undocumented | Likely vendor-specific thermal/power MSR |
| 0x1147 | Undocumented | Likely vendor-specific thermal/power MSR |
| 0xC0000086 | AMD specific | AMD processor-specific MSR |

**Any MSR not in this whitelist returns 0xC0000022 (STATUS_ACCESS_DENIED).**

### Additional Check

- MSR index == 0 is rejected with STATUS_ILLEGAL_INSTRUCTION (0xC000001D), same as RDMSR.
- The whitelist check happens BEFORE the null check, so null is technically caught by "not in whitelist" first.

### Operation

```asm
mov ecx, [input_msr_index]     ; MSR number
mov eax, [input_value_low]     ; Lower 32 bits
mov edx, [input_value_high]    ; Upper 32 bits (from shr rdx, 0x20 of combined qword)
wrmsr                           ; Execute WRMSR
```

### Return Values

| Status | Meaning |
|--------|---------|
| STATUS_SUCCESS (0) | MSR written, IoStatus.Information = 0x0C |
| 0xC0000022 | STATUS_ACCESS_DENIED — MSR not in whitelist |
| 0xC000001D | STATUS_ILLEGAL_INSTRUCTION — MSR index is 0 |

### Error Handling

- **No __try/__except around WRMSR!** Writing to a non-writable or non-existent whitelisted MSR would #GP → BSOD
- However, the whitelist restricts to known-safe MSRs so this shouldn't happen in practice
- The whitelist effectively limits WRMSR to performance counter configuration

---

## Security Analysis

### RDMSR Exploitation Potential

RDMSR with only 2 blacklisted entries is highly exploitable:
- **Kernel base discovery:** Read IA32_LSTAR (0xC0000082) to get KiSystemCall64
- **Thread/process identification:** Read IA32_GS_BASE (0xC0000101) for KPCR → ETHREAD
- **Page table base:** Combine with physical memory reads to walk page tables
- **KASLR defeat:** Any of the above reveals kernel ASLR slide

### WRMSR Exploitation Potential

Limited by whitelist to 6 MSRs. The performance counter MSRs (0x38D, 0x38F) could potentially be used for:
- Side-channel attacks (enable/configure PMCs)
- Timing attacks

The whitelist prevents writing to dangerous MSRs like:
- IA32_LSTAR (redirect syscalls)
- IA32_SYSENTER_EIP (legacy syscall hook)
- IA32_EFER (disable NX/SMEP)
- IA32_STAR (syscall segment selectors)

---

## Rust FFI Implementation

```rust
/// Read an MSR via SIVX64.sys
pub fn rdmsr(handle: HANDLE, msr_index: u32) -> Result<u64, NTSTATUS> {
    let input = msr_index.to_le_bytes();
    let mut output = [0u8; 8];
    let mut bytes_returned: u32 = 0;
    
    let ok = unsafe {
        DeviceIoControl(
            handle,
            0x08,                    // IOCTL_RDMSR
            input.as_ptr() as _,
            4,
            output.as_mut_ptr() as _,
            8,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };
    
    if ok != 0 && bytes_returned == 8 {
        Ok(u64::from_le_bytes(output))
    } else {
        Err(get_last_ntstatus())
    }
}

/// Write an MSR via SIVX64.sys (whitelist enforced)
pub fn wrmsr(handle: HANDLE, msr_index: u32, value: u64) -> Result<(), NTSTATUS> {
    let mut input = [0u8; 12];
    input[0..4].copy_from_slice(&msr_index.to_le_bytes());
    input[4..8].copy_from_slice(&(value as u32).to_le_bytes());      // low 32
    input[8..12].copy_from_slice(&((value >> 32) as u32).to_le_bytes()); // high 32
    
    let mut output = [0u8; 12];
    let mut bytes_returned: u32 = 0;
    
    let ok = unsafe {
        DeviceIoControl(
            handle,
            0x0C,                    // IOCTL_WRMSR
            input.as_ptr() as _,
            12,
            output.as_mut_ptr() as _,
            12,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };
    
    if ok != 0 {
        Ok(())
    } else {
        Err(get_last_ntstatus())
    }
}
```
