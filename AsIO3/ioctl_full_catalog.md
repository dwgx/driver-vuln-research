# AsIO3 (Asusgio3.sys) Complete IOCTL Catalog

## Summary

- **Driver**: Asusgio3.sys (ASUS AsIO3 hardware monitor)
- **Total IOCTLs with handlers**: 39
- **Total dispatch entries** (including rejected): 41
- **Device type**: 0xA040 (custom)
- **All methods**: BUFFERED (method 0)
- **Validation mechanisms**: g_goodRanges (physical memory), Port whitelist, MSR whitelist

---

## Validation Mechanisms

### g_goodRanges (Physical Memory Validation)

Called by: `sub_140001514`

**Hardcoded ranges** (always allowed):
| Base | End | Description |
|------|-----|-------------|
| 0x000E0000 | 0x000FFFFF | Legacy BIOS/Video ROM area |
| 0xF8000000 | 0xFFFFFFFF | PCI MMIO / High BIOS (4GB-128MB to 4GB) |

**Dynamic ranges**: Loaded from a linked list (`g_goodRanges` at RVA 0x9670). Additional ranges can be added via registry or runtime configuration. Also checks a secondary dynamic table loaded from a config structure.

**Bypass**: Only applies to IOCTLs 0xA040200C, 0xA0400F80, 0xA0400F84, 0xA0400F7C, 0xA040244C/A480. Does NOT apply to MSR, Port I/O, PCI config, or bus data operations.

### Port Whitelist

Called by: `sub_14000143C`

43 port ranges allowed (see appendix). Notably includes:
- 0x0CF8-0x0CF9, 0x0CFC (PCI config space ports)
- 0x002E-0x002F (Super I/O index/data)
- 0x00B2 (SMI trigger port)

### MSR Whitelist

Called by: `sub_1400014BC`

29 MSR values allowed (see appendix). Notably EXCLUDES:
- 0xC0000080 (IA32_EFER) - cannot disable SMEP/SMAP
- 0xC0000082 (IA32_LSTAR) - cannot read syscall handler address
- 0xC0000100/101/102 (FS/GS base) - cannot read KPCR
- 0x1B (IA32_APIC_BASE)
- 0x176 (IA32_SYSENTER_EIP)

---

## IOCTL Categories

### Category A: Physical Memory Access (11 IOCTLs)

| # | IOCTL Code | Name | has_range_check | exploitation_potential |
|---|-----------|------|-----------------|----------------------|
| 1 | 0xA040200C | PhysMem_MapSection | YES | HIGH - Maps physical memory via ZwOpenSection + ZwMapViewOfSection. Range-limited to g_goodRanges |
| 2 | 0xA0402010 | PhysMem_UnmapSection | NO | LOW - Unmaps previously mapped section |
| 3 | 0xA0400F80 | PhysMem_WriteSmall | YES | HIGH - Maps physical page, writes 1/2/4 bytes, unmaps. Range-limited |
| 4 | 0xA0400F84 | PhysMem_ReadPage | YES | HIGH - Maps physical page, copies 0x1000 bytes to user buffer, unmaps. Range-limited |
| 5 | 0xA0400F7C | PhysMem_Unmap_ReadPage | YES | HIGH - Same as F84 (different struct variant for 32-bit callers) |
| 6 | 0xA040244C | PhysMem_MapContiguous_32bit | YES | HIGH - ZwOpenSection-based map for 32-bit callers, with range check |
| 7 | 0xA040A480 | PhysMem_MapContiguous_64bit | YES | HIGH - Same as 244C but with 0x28-byte struct for 64-bit callers |
| 8 | 0xA0402450 | PhysMem_FreeMapping | NO | LOW - Frees a previously established mapping |
| 9 | 0xA040A488 | PhysMem_AllocDMA | NO | MEDIUM - MmAllocateContiguousMemory + MmGetPhysicalAddress. Returns virtual+physical address pair |
| 10 | 0xA040A48C | PhysMem_FreeDMA | NO | LOW - Frees from tracking list (removes linked list entry) |
| 11 | 0xA040A490 | PhysMem_RegisterVA | NO | LOW - Stores a virtual address in a slot table for later use |

**Input/Output Structures (Physical Memory)**:

**0xA040200C** (MapSection):
```c
// Input (0x1028 bytes for 32-bit, larger for 64-bit):
struct {
    ULONG64 mapped_va;       // +0x08: returned mapped VA
    ULONG   size;            // +0x10: size to map
    ULONG   phys_addr_lo;   // +0x14: physical address (32-bit path)
    ULONG64 phys_addr;      // +0x18: physical address (64-bit path)
    ULONG64 section_handle; // +0x20: returned section object
};
// Calls sub_140004018: range_check -> ZwOpenSection(\Device\PhysicalMemory) -> ZwMapViewOfSection
```

**0xA0400F84** (ReadPage):
```c
// Input/Output (0x1028 bytes):
struct {
    BYTE    data_type;       // +0x00: unused (always reads full page)
    ULONG64 mapped_va;       // +0x08: VA of previously mapped region
    ULONG   size;            // +0x10: size to read (always 0x1000)
    ULONG   phys_addr_lo;   // +0x14: physical address (32-bit)
    ULONG64 phys_addr;      // +0x18: physical address (64-bit)
    ULONG64 section_handle; // +0x20: returned section object
    BYTE    page_data[4096]; // +0x28: output data (full page copy)
};
```

**0xA0400F80** (WriteSmall):
```c
// Input (0x1028 bytes):
struct {
    BYTE    data_type;       // +0x00: 1=byte, 2=word, 4=dword
    BYTE    write_byte;      // +0x01: byte to write (if type==1)
    WORD    write_word;      // +0x02: word to write (if type==2)
    DWORD   write_dword;     // +0x04: dword to write (if type==4)
    ULONG64 mapped_va;       // +0x08: VA of mapped region
    ULONG   size;            // +0x10: unused
    ULONG   phys_addr_lo;   // +0x14: physical address (32-bit)
    ULONG64 phys_addr;      // +0x18: physical address (64-bit)
    ULONG64 section_handle; // +0x20: section handle
};
```

### Category B: MSR Operations (4 IOCTLs)

| # | IOCTL Code | Name | has_range_check | exploitation_potential |
|---|-----------|------|-----------------|----------------------|
| 12 | 0xA0400F88 | MSR_Read | MSR_WHITELIST | MEDIUM - rdmsr with MSR whitelist. Limited to 29 allowed MSR values |
| 13 | 0xA0400F8C | MSR_Write | MSR_WHITELIST | MEDIUM - wrmsr with MSR whitelist. Cannot write IA32_LSTAR or EFER |
| 14 | 0xA0406458 | MSR_Read_Extended | MSR_WHITELIST | MEDIUM - rdmsr with different struct format, same whitelist |
| 15 | 0xA040A45C | MSR_WriteAndReadback | MSR_WHITELIST | MEDIUM - wrmsr then rdmsr (verify write), same whitelist |

**Input/Output Structures (MSR)**:

**0xA0400F88** (MSR_Read):
```c
// Input/Output (0x10 bytes):
struct {
    DWORD   msr_index;    // +0x00: MSR register number (checked against whitelist)
    ULONG64 msr_value;    // +0x08: output - 64-bit MSR value (edx:eax)
};
```

**0xA0400F8C** (MSR_Write):
```c
// Input (0x10 bytes):
struct {
    DWORD   msr_index;    // +0x00: MSR register number (checked against whitelist)
    ULONG64 msr_value;    // +0x08: value to write (split into edx:eax)
};
```

**0xA0406458** (MSR_Read_Extended):
```c
// Input/Output (8 bytes minimum):
struct {
    DWORD   msr_index;    // +0x00: MSR register number (checked against whitelist)
    // Output: entire 8-byte struct overwritten with 64-bit MSR value
};
```

**0xA040A45C** (MSR_WriteAndReadback):
```c
// Input/Output (0x0C bytes):
struct {
    DWORD   msr_index;    // +0x00: MSR register number
    ULONG64 write_value;  // +0x04: value to write
    // Output: struct overwritten with readback value (8 bytes at offset 0)
};
```

### Category C: PCI Configuration Space (7 IOCTLs)

| # | IOCTL Code | Name | has_range_check | exploitation_potential |
|---|-----------|------|-----------------|----------------------|
| 16 | 0xA0400F58 | PCI_CfgRead | PORT_WHITELIST | HIGH - Read PCI config via CF8/CFC. Can read BAR addresses |
| 17 | 0xA0400F5C | PCI_CfgWrite | PORT_WHITELIST | HIGH - Write PCI config via CF8/CFC. Can modify BAR values |
| 18 | 0xA0400F70 | PCI_CfgReadBulk | PORT_WHITELIST | HIGH - Bulk read PCI config space (loop of CF8/CFC) |
| 19 | 0xA0402000 | PCI_HalGetBusData | NO | HIGH - HalGetBusDataByOffset. No restrictions on bus/dev/func/offset |
| 20 | 0xA0402004 | PCI_HalSetBusData | NO | HIGH - HalSetBusDataByOffset. No restrictions |
| 21 | 0xA0402014 | PCI_ExtendedWrite | PORT_WHITELIST | HIGH - Extended PCI config write with full topology |
| 22 | 0xA0402018 | PCI_ExtendedRead | PORT_WHITELIST | HIGH - Extended PCI config read with full topology |

**Input/Output Structures (PCI Config)**:

**0xA0400F58** (PCI_CfgRead via CF8/CFC):
```c
// Input/Output (0x14 bytes):
struct {
    BYTE    data_type;     // +0x00: 1=byte, 2=word, 4=dword
    DWORD   cf8_address;   // +0x04: PCI config address for port 0xCF8
    WORD    port_number;   // +0x08: unused
    DWORD   read_dword;    // +0x0C: output (type=4)
    WORD    read_word;     // +0x10: output (type=2)
    BYTE    read_byte;     // +0x12: output (type=1)
};
// Operation: OUT CF8, [cf8_address]; IN CFC -> result by type
```

**0xA0402000** (HalGetBusData):
```c
// Input/Output (0x14 bytes):
struct {
    BYTE    data_type;     // +0x00: 1=byte, 2=word, 4=dword
    DWORD   bus_number;    // +0x04: encoded (bits for bus/dev/func)
    BYTE    offset;        // +0x06: PCI config offset
    // Output: value written back at appropriate size
};
// Calls: HalGetBusDataByOffset(PCIConfiguration, bus, slot, &buffer, offset, size)
```

### Category D: Port I/O - Direct (6 IOCTLs)

| # | IOCTL Code | Name | has_range_check | exploitation_potential |
|---|-----------|------|-----------------|----------------------|
| 23 | 0xA0406400 | PortIO_ReadByte | PORT_WHITELIST | MEDIUM - `IN al, dx` with whitelist |
| 24 | 0xA0406404 | PortIO_ReadWord | PORT_WHITELIST | MEDIUM - `IN ax, dx` with whitelist |
| 25 | 0xA0406408 | PortIO_ReadDword | PORT_WHITELIST | MEDIUM - `IN eax, dx` with whitelist |
| 26 | 0xA040A440 | PortIO_WriteByte | PORT_WHITELIST | MEDIUM - `OUT dx, al` with whitelist |
| 27 | 0xA040A444 | PortIO_WriteWord | PORT_WHITELIST | MEDIUM - `OUT dx, ax` with whitelist |
| 28 | 0xA040A448 | PortIO_WriteDword | PORT_WHITELIST | MEDIUM - `OUT dx, eax` with whitelist |

**Input/Output Structures (Direct Port I/O)**:

**Read (0xA0406400/6404/6408)** - 32-bit path uses HalTranslateBusAddress:
```c
// Input/Output (4 bytes):
struct {
    DWORD   port_address;  // +0x00: I/O port address
    // Output: value written back (byte/word/dword depending on IOCTL)
};
```

**Write (0xA040A440/A444/A448)** - 64-bit path:
```c
// Input (0x0C bytes):
struct {
    WORD    port_number;   // +0x00: I/O port address (from buffer copy)
    BYTE    data_type;     // +0x08: 1=byte, 2=word, 4=dword
    DWORD   write_value;   // +0x04: value to write
};
```

### Category E: Port I/O - Indexed/Sequential (6 IOCTLs)

| # | IOCTL Code | Name | has_range_check | exploitation_potential |
|---|-----------|------|-----------------|----------------------|
| 29 | 0xA0400F60 | PortIO_IndexedRead | PORT_WHITELIST | MEDIUM - Sequential IN with port whitelist |
| 30 | 0xA0400F64 | PortIO_IndexedWrite | PORT_WHITELIST | MEDIUM - OUT byte/word/dword to whitelisted port |
| 31 | 0xA0400F68 | PortIO_IndexedRW_Byte | PORT_WHITELIST | MEDIUM - OUT index byte then jump |
| 32 | 0xA0400F6C | PortIO_IndexedRW_Word | PORT_WHITELIST | MEDIUM - OUT index byte then jump |
| 33 | 0xA0400F74 | PortIO_SequentialRead | PORT_WHITELIST | MEDIUM - Loop: IN al,dx with incrementing port |
| 34 | 0xA0400F78 | PortIO_BulkWrite | PORT_WHITELIST | MEDIUM - Loop: OUT with offset pattern |

**Input/Output Structures (Indexed Port I/O)**:

**0xA0400F70** (PCI_CfgReadBulk):
```c
// Input/Output (0x20C bytes):
struct {
    DWORD   cf8_start;     // +0x00: starting CF8 address
    WORD    port;          // +0x04: base port
    BYTE    index_byte;    // +0x06: index register value
    WORD    count;         // +0x08: number of DWORDs to read
    BYTE    data[0x200];   // +0x0A: output buffer
};
// Operation: loop { OUT CF8, addr; IN CFC; addr += 4 } until count reached
```

### Category F: Contiguous Memory Management (2 IOCTLs)

| # | IOCTL Code | Name | has_range_check | exploitation_potential |
|---|-----------|------|-----------------|----------------------|
| 35 | 0xA0400F90 | ContigMem_Allocate | NO | MEDIUM - MmAllocateContiguousMemory + MmGetPhysicalAddress |
| 36 | 0xA0400F94 | ContigMem_Free | NO | LOW - MmFreeContiguousMemory |

**Input/Output Structures (Contiguous Memory)**:

**0xA0400F90** (ContigMem_Allocate):
```c
// Input/Output (0x1028 bytes):
struct {
    ULONG   alloc_size;    // +0x10: size (max 128MB)
    ULONG64 phys_addr;     // +0x18: output physical address
    ULONG64 virt_addr;     // +0x20: output kernel virtual address
};
// Returns kernel VA and physical address of contiguous memory allocation
```

### Category G: Bus Data Operations (3 IOCTLs)

| # | IOCTL Code | Name | has_range_check | exploitation_potential |
|---|-----------|------|-----------------|----------------------|
| 37 | 0xA040A540 | BusData_Byte | NO | HIGH - Port I/O with full register context. NO WHITELIST |
| 38 | 0xA040A544 | BusData_Word | NO | HIGH - Same, word-sized |
| 39 | 0xA040A548 | BusData_Dword | NO | HIGH - Same, dword-sized |

**Input/Output Structures (Bus Data)**:

```c
// Input (0x24 bytes):
struct {
    DWORD   port_number;   // +0x00: port for initial OUT
    DWORD   reg_ebx;       // +0x04: saved register context
    DWORD   reg_ecx;       // +0x08: saved register context
    DWORD   reserved;      // +0x0C:
    DWORD   reg_esi;       // +0x10: saved register context
    DWORD   reg_edi;       // +0x14: saved register context
    DWORD   reg_ebp;       // +0x18: saved register context
    DWORD   data_value;    // +0x20: value/output
};
// Direction determined by internal flag:
//   WRITE: does OUT port, value (byte/word/dword per IOCTL)
//   READ: reads from memory-mapped address to output
// CRITICAL: NO PORT WHITELIST CHECK on these IOCTLs!
```

---

## Exploitation Analysis

### Tier 1: Bus Data IOCTLs Bypass Port Whitelist (0xA040A540-A548)

These call `sub_1400012A0` which does raw `OUT dx, al/ax/eax` with NO port whitelist check. The port number comes directly from user input. This enables:

1. **Access ANY I/O port**: CF8/CFC, SMI port, any device I/O
2. **PCI config manipulation**: Write CF8 then read/write CFC
3. **SMI triggering**: Write to port 0xB2

Limitation: These only perform OUTPUT in the direct-call path. The read-back path writes to a memory-mapped location from the input struct context.

### Tier 2: PCI Config (Unrestricted via HAL APIs)

**0xA0402000** (HalGetBusData) and **0xA0402004** (HalSetBusData) have NO validation on bus/dev/func/offset. Full PCI config space access enables:

1. Read any device BAR to find MMIO mappings
2. Write BARs to remap device MMIO to target physical addresses
3. Read device-specific config (DMA descriptors, etc.)

### Tier 3: Physical Memory (Range-Limited)

All physical memory IOCTLs are limited to g_goodRanges:
- 0xE0000-0xFFFFF (128KB BIOS area)
- 0xF8000000-0xFFFFFFFF (128MB PCI MMIO space)

**PCI BAR Remap Attack**:
1. Use 0xA0402000 to enumerate PCI devices and read current BARs
2. Find a device with an MMIO BAR in the 0xF8000000+ range
3. Use 0xA0402004 to reprogram that BAR to point to target physical memory
4. Use 0xA0400F84 to read the now-remapped MMIO region
5. Risk: system instability if device is actively using the BAR

### Tier 4: MSR Access (Whitelist-Limited)

MSR operations are restricted to 29 power/thermal/performance MSRs. Cannot read:
- IA32_LSTAR (kernel base disclosure)
- GS_BASE (KPCR/KTHREAD)
- IA32_EFER (security feature bypass)

---

## Appendix A: MSR Whitelist (29 entries)

| # | MSR | Name |
|---|-----|------|
| 0 | 0x00000035 | MSR_CORE_THREAD_COUNT |
| 1 | 0x000000CE | MSR_PLATFORM_INFO |
| 2 | 0x00000150 | Intel Erratum |
| 3 | 0x00000194 | CLOCK_MODULATION |
| 4 | 0x00000198 | IA32_PERF_STATUS |
| 5 | 0x000001A2 | MSR_TEMPERATURE_TARGET |
| 6 | 0x000001B1 | IA32_PACKAGE_THERM_STATUS |
| 7 | 0x000001A0 | IA32_MISC_ENABLE |
| 8 | 0x000001AD | MSR_TURBO_RATIO_LIMIT |
| 9 | 0x000001AE | MSR_TURBO_RATIO_LIMIT1 |
| 10 | 0x00000606 | MSR_RAPL_POWER_UNIT |
| 11 | 0x00000610 | MSR_PKG_POWER_LIMIT |
| 12 | 0x00000611 | MSR_PKG_ENERGY_STATUS |
| 13 | 0x00000614 | MSR_PKG_POWER_INFO |
| 14 | 0x00000620 | MSR_UNCORE_RATIO_LIMIT |
| 15 | 0x00000650 | MSR_CORE_PERF_LIMIT |
| 16 | 0x00000651 | MSR_CORE_PERF_LIMIT1 |
| 17 | 0x00000770 | IA32_PM_ENABLE |
| 18 | 0x00000774 | IA32_HWP_REQUEST |
| 19 | 0xC0010015 | AMD HWCR |
| 20 | 0xC0010061 | AMD P-State Current Limit |
| 21 | 0xC0010062 | AMD P-State Control |
| 22 | 0xC0010063 | AMD P-State Status |
| 23 | 0xC0010064 | AMD P-State 0 |
| 24 | 0xC0010065 | AMD P-State 1 |
| 25 | 0xC0010066 | AMD P-State 2 |
| 26 | 0xC0010071 | AMD CPUID Features |
| 27 | 0xC0010292 | AMD RAPL PKG |
| 28 | 0xC0010293 | AMD RAPL CORE |

## Appendix B: Port Whitelist (43 ranges)

| # | Start | End | Use |
|---|-------|-----|-----|
| 0 | 0x002E | 0x002F | Super I/O index/data |
| 1 | 0x0040 | 0x005E | PIT/DMA/PIC |
| 2 | 0x0060 | 0x006E | PS/2 keyboard |
| 3 | 0x0070 | 0x007E | CMOS/RTC |
| 4 | 0x0080 | 0x0080 | DMA page register |
| 5 | 0x0084 | 0x008E | DMA page registers |
| 6 | 0x00B2 | 0x00B2 | **SMI trigger** |
| 7 | 0x00E0 | 0x00E0 | ISA |
| 8 | 0x00EB | 0x00EB | I/O delay |
| 9 | 0x00ED | 0x00ED | I/O delay |
| 10 | 0x0200 | 0x021F | Game port |
| 11 | 0x025C | 0x025D | Winbond |
| 12 | 0x0270 | 0x0270 | LPT |
| 13 | 0x0278 | 0x027E | LPT2 |
| 14 | 0x0295 | 0x0296 | Winbond/SMSC |
| 15 | 0x02A0 | 0x02AE | ISA |
| 16 | 0x02C0 | 0x02C0 | ISA |
| 17 | 0x02C2 | 0x02C5 | ISA |
| 18 | 0x02CE | 0x02CE | ISA |
| 19 | 0x02E8 | 0x02EE | COM4 |
| 20 | 0x02F8 | 0x02FE | COM2 |
| 21 | 0x0378 | 0x037E | LPT1 |
| 22 | 0x0381 | 0x0383 | ISA |
| 23 | 0x03E8 | 0x03EE | COM3 |
| 24 | 0x03F8 | 0x03FE | COM1 |
| 25 | 0x0406 | 0x0406 | ISA |
| 26 | 0x0500 | 0x0500 | SMBus |
| 27 | 0x0502 | 0x0502 | SMBus |
| 28 | 0x0800 | 0x0805 | ACPI |
| 29 | 0x0830 | 0x0830 | ACPI |
| 30 | 0x0A00 | 0x0A7F | IT87xx HW monitor |
| 31 | 0x0AA0 | 0x0AA6 | IT87xx |
| 32 | 0x0B00 | 0x0B3E | Nuvoton HW monitor |
| 33 | 0x0CD6 | 0x0CD7 | AMD FCH index/data |
| 34 | 0x0CF8 | 0x0CF9 | **PCI config address** |
| 35 | 0x0CFC | 0x0CFC | **PCI config data** |
| 36 | 0x1800 | 0x1800 | Intel PCH |
| 37 | 0x1802 | 0x1802 | Intel PCH |
| 38 | 0x1830 | 0x1830 | Intel PCH |
| 39 | 0x1C00 | 0x1C3E | Intel PCH SMBus |
| 40 | 0xEFA0 | 0xEFBE | Embedded Controller |
| 41 | 0xF000 | 0xF00E | Custom |
| 42 | 0xF040 | 0xF07E | Custom |

## Appendix C: Physical Memory Hardcoded Ranges (g_goodRanges static)

| Base | End | Size | Description |
|------|-----|------|-------------|
| 0x000E0000 | 0x000FFFFF | 128 KB | Legacy BIOS/Video ROM |
| 0xF8000000 | 0xFFFFFFFF | 128 MB | PCI MMIO / High BIOS |

---

## Verdict for VRChat Key Extraction

**Can this driver read arbitrary process memory?** NO, not directly. The g_goodRanges restriction prevents accessing typical process physical memory pages (which reside well below 0xF8000000).

**Exploitable paths** (ordered by feasibility):

1. **PCI BAR Remap** (0xA0402000 + 0xA0402004 + 0xA0400F84): Remap a PCIe device BAR to target physical address, then read via the allowed MMIO range. HIGH RISK of system crash.

2. **Bus Data port bypass** (0xA040A540-A548): Access any port without whitelist. Enables advanced attacks but only output direction is clearly available.

3. **g_goodRanges dynamic expansion**: If the driver's dynamic range list can be manipulated (e.g., via registry key that populates it), additional physical ranges become accessible.

**Recommendation**: AsIO3 is NOT suitable for reliable VRChat memory key extraction. Use SIVX64.sys or ASMMAP64.sys which have no range restrictions on physical memory access.
