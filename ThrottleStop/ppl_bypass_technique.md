# ThrottleStop PPL Bypass via MmMapLockedPagesSpecifyCache

## Physical Memory Mapping Mechanism

ThrottleStop.sys IOCTL `0x8000645C` provides persistent user-mode physical memory mappings:

1. `MmMapIoSpace(PhysAddr, Size, MmNonCached)` -- kernel VA from physical address, NO range check
2. `IoAllocateMdl(KernelVA, Size)` -- allocate MDL describing the pages
3. `MmBuildMdlForNonPagedPool(Mdl)` -- populate MDL PFN array
4. `MmMapLockedPagesSpecifyCache(Mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority)` -- map into calling process VA space

Result: user-mode pointer to arbitrary physical memory. Up to 256 concurrent mappings tracked by PID. No address validation whatsoever.

## PPL Bypass Flow

```
1. DeviceIoControl(hDevice, 0x8000645C, {EPROCESS_PA + 0x800, 0x100}, ...)
   -> Returns user-mode ptr to physical page containing Protection field
2. *(BYTE*)(ptr + (0x87A & 0xFFF)) = 0x00
   -> Clears PS_PROTECTION in-place via user-mode write
3. DeviceIoControl(hDevice, 0x80006460, {ptr}, ...)
   -> Unmap when done
```

Key advantage: the write happens from user-mode code through a mapped page. No IOCTL write command needed -- just a pointer dereference. This is faster and leaves fewer traces than issuing a separate write IOCTL per byte.

## Comparison: ThrottleStop vs LnvMSRIO

| Aspect | ThrottleStop (0x8000645C) | LnvMSRIO |
|--------|--------------------------|----------|
| Mapping API | MmMapLockedPagesSpecifyCache (user-mode map) | MmMapIoSpace (kernel-only) |
| Write method | Direct pointer deref in user-mode | Separate IOCTL per write |
| Range check | None | None |
| Persistence | Mapped until explicit unmap | Map/unmap per IOCTL call |
| Signing | EV Code Signed (DigiCert) | Lenovo OEM signed |
| IOCTL overhead | 1 call to map, then zero-cost R/W | 1 IOCTL per read/write op |
| Extra primitives | MSR, I/O port, PCI config | MSR only |

ThrottleStop's persistent user-mode mapping means scanning physical memory (e.g., walking EPROCESS list) is significantly faster -- map a 4KB page once, read it freely, unmap. LnvMSRIO requires one IOCTL round-trip per 8-byte read.

## Detection Status

- Listed on LOLDrivers (loldrivers.io) under CVE-2025-7771
- SHA-256: `16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0`
- Windows Defender WDAC/HVCI blocklist: likely to be added if not already
- EAC/BattlEye: unknown detection status (ThrottleStop is legitimate CPU tuning software, widely installed)

Still useful as fallback because:
- Legitimate software with millions of users (unlike purpose-built exploit drivers)
- EV-signed by recognized publisher, not cross-signed
- ThrottleStop utility is commonly installed on gaming/overclocking machines
- Service name `ThrottleStop` looks benign in driver enumeration

## CVE-2025-7771 Reference Implementation

Repository: `github.com/xM0kht4r/CVE-2025-7771`

Contains a full Rust implementation demonstrating:
- Driver loading via service manager
- IOCTL wrapper for all 11 commands
- Physical memory map/unmap with user-mode pointer access
- EPROCESS traversal and PPL bypass proof-of-concept

Directly applicable to toolkit's `driver_chain.rs` as an additional fallback driver. The Rust IOCTL definitions and MDL-based mapping flow can be adapted with minimal changes.

## Operational Notes

- Requires Administrator (SDDL: `D:P(A;;GA;;;SY)(A;;GA;;;BA)`)
- Max 256 concurrent mappings (driver limit)
- Still subject to the kernel safety rules: DO NOT use for user-mode page table traversal (5 BSoDs prove this path is dead regardless of driver)
- Safe use case: map EPROCESS page (kernel address from Superfetch/vtop table), write Protection byte, unmap
- The user-mode mapping primitive does NOT make user-mode PTE traversal safe -- the BSoD risk is in MmMapIoSpace being called on transition/prototype PTEs, which this driver also uses internally
