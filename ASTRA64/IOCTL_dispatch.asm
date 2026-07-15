; ASTRA64.sys - IRP_MJ_DEVICE_CONTROL Dispatch Handler
; Function VA: 0x11280 - 0x11694  (RVA 0x1280, 1044 bytes code + jump tables)
;
; Switch dispatch mechanism:
;   1. Extract IOCTL code from IRP stack (IoGetCurrentIrpStackLocation)
;   2. Subtract base code 0x80002008 (via ADD 0x7FFFDFF8)
;   3. Compare against max offset 0xE4 (228)
;   4. Two-level jump table: byte index -> dword offset -> handler
;
; IOCTL Code Table (31 valid handlers):
;
;   0x80002008  IOCTL_PHYS_MAP            ZwMapViewOfSection(\Device\PhysicalMemory)
;   0x8000200c  IOCTL_PHYS_UNMAP          ZwUnmapViewOfSection
;   0x80002010  IOCTL_PHYS_MAP_EX         ExAllocatePoolWithTag + RtlCopyMemory (alloc+copy)
;   0x80002014  IOCTL_PHYS_UNMAP_EX       MmUnmapLockedPages + IoFreeMdl + ExFreePoolWithTag
;   0x80002018  IOCTL_IRQ_DISCONNECT      IoDisconnectInterrupt + MmUnmapIoSpace + IoFreeMdl
;   0x8000201c  IOCTL_IRQ_DISCONNECT2     IoDisconnectInterrupt + MmUnmapIoSpace + IoFreeMdl
;   0x80002020  IOCTL_IRQ_CONNECT         IoConnectInterrupt
;   0x80002024  IOCTL_EVENT_SET           KeSetEvent
;   0x80002028  IOCTL_PORT_IN_1           IN al, dx (READ_PORT_UCHAR)
;   0x8000202c  IOCTL_PORT_IN_2           IN ax, dx (READ_PORT_USHORT)
;   0x80002030  IOCTL_PORT_IN_4           IN eax, dx (READ_PORT_ULONG)
;   0x80002034  IOCTL_PORT_OUT_1          OUT dx, al (WRITE_PORT_UCHAR)
;   0x80002038  IOCTL_PORT_OUT_2          OUT dx, ax (WRITE_PORT_USHORT)
;   0x8000203c  IOCTL_PORT_OUT_4          OUT dx, eax (WRITE_PORT_ULONG)
;   0x80002040  IOCTL_PORT_IN_BUF_1       REP INSB (buffered port read, 1-byte)
;   0x80002044  IOCTL_PORT_IN_BUF_2       REP INSW (buffered port read, 2-byte)
;   0x80002048  IOCTL_PORT_IN_BUF_4       REP INSD (buffered port read, 4-byte)
;   0x8000204c  IOCTL_PORT_OUT_BUF_1      REP OUTSB (buffered port write, 1-byte)
;   0x80002050  IOCTL_PORT_OUT_BUF_2      REP OUTSW (buffered port write, 2-byte)
;   0x80002054  IOCTL_PORT_OUT_BUF_4      REP OUTSD (buffered port write, 4-byte)
;   0x80002064  IOCTL_PCI_READ            PCI config read (bus scan + read via 0xCF8/0xCFC)
;   0x80002068  IOCTL_UNKNOWN_68          Unknown handler at 0x12050
;   0x8000206c  IOCTL_UNKNOWN_6C          Unknown handler at 0x12070
;   0x80002070  IOCTL_NOOP_70             Returns STATUS_SUCCESS (noop)
;   0x80002074  IOCTL_NOOP_74             Returns STATUS_SUCCESS (noop)
;   0x8000207c  IOCTL_EVENT_SET2          KeSetEvent (alternate)
;   0x80002084  IOCTL_MEM_COPY_84         RtlCopyMemory x2
;   0x80002088  IOCTL_MEM_COPY_88         RtlCopyMemory x2
;   0x8000208c  IOCTL_MEM_FREE            MmUnmapLockedPages + IoFreeMdl + MmFreeContiguousMemory
;   0x800020a0  IOCTL_PCI_SCAN            PCI bus/dev/func enumeration + config read
;   0x800020a4  IOCTL_PCI_WRITE           PCI config write via 0xCF8/0xCFC
;   0x800020e8  IOCTL_EVENT_CREATE        IoCreateNotificationEvent (keyboard/IRQ)
;   0x800020ec  IOCTL_MSR_READ            RDMSR instruction (read Model-Specific Register)
;
; === Main Dispatch (first 200 lines) ===
  0000000000011280  53                        push     rbx
  0000000000011281  57                        push     rdi
  0000000000011282  4883ec38                  sub      rsp, 0x38
  0000000000011286  488bfa                    mov      rdi, rdx
  0000000000011289  33db                      xor      ebx, ebx
  000000000001128B  48895f38                  mov      qword ptr [rdi + 0x38], rbx
  000000000001128F  4c8b9fb8000000            mov      r11, qword ptr [rdi + 0xb8]
  0000000000011296  4c8b5718                  mov      r10, qword ptr [rdi + 0x18]
  000000000001129A  458b4b10                  mov      r9d, dword ptr [r11 + 0x10]
  000000000001129E  458b4308                  mov      r8d, dword ptr [r11 + 8]
  00000000000112A2  488b5140                  mov      rdx, qword ptr [rcx + 0x40]
  00000000000112A6  418a03                    mov      al, byte ptr [r11]
  00000000000112A9  84c0                      test     al, al
  00000000000112AB  0f84bb030000              je       0x1166c
  00000000000112B1  3c02                      cmp      al, 2
  00000000000112B3  0f84a1030000              je       0x1165a
  00000000000112B9  3c0e                      cmp      al, 0xe
  00000000000112BB  741d                      je       0x112da
  00000000000112BD  3c12                      cmp      al, 0x12
  00000000000112BF  0f85b9030000              jne      0x1167e
  00000000000112C5  4489442420                mov      dword ptr [rsp + 0x20], r8d
  00000000000112CA  4c8bc7                    mov      r8, rdi
  00000000000112CD  498bca                    mov      rcx, r10
  00000000000112D0  e83b130000                call     0x12610
  00000000000112D5  e9a2030000                jmp      0x1167c
  00000000000112DA  418b4318                  mov      eax, dword ptr [r11 + 0x18]
  00000000000112DE  05f8dfff7f                add      eax, 0x7fffdff8
  00000000000112E3  3de4000000                cmp      eax, 0xe4
  00000000000112E8  0f8765030000              ja       0x11653
  00000000000112EE  488d0d2b040000            lea      rcx, [rip + 0x42b]
  00000000000112F5  480fb60401                movzx    rax, byte ptr [rcx + rax]
  00000000000112FA  488d0d97030000            lea      rcx, [rip + 0x397]
  0000000000011301  48630481                  movsxd   rax, dword ptr [rcx + rax*4]
  0000000000011305  488d0d05000000            lea      rcx, [rip + 5]
  000000000001130C  4803c1                    add      rax, rcx
  000000000001130F  ffe0                      jmp      rax
  0000000000011311  4489442420                mov      dword ptr [rsp + 0x20], r8d
  0000000000011316  4c8bc7                    mov      r8, rdi
  0000000000011319  498bca                    mov      rcx, r10
  000000000001131C  e8bf070000                call     0x11ae0
  0000000000011321  e956030000                jmp      0x1167c
  0000000000011326  4489442420                mov      dword ptr [rsp + 0x20], r8d
  000000000001132B  4c8bc7                    mov      r8, rdi
  000000000001132E  498bca                    mov      rcx, r10
  0000000000011331  e80a080000                call     0x11b40
  0000000000011336  e941030000                jmp      0x1167c
  000000000001133B  4489442420                mov      dword ptr [rsp + 0x20], r8d
  0000000000011340  4c8bc7                    mov      r8, rdi
  0000000000011343  498bca                    mov      rcx, r10
  0000000000011346  e845080000                call     0x11b90
  000000000001134B  e92c030000                jmp      0x1167c
  0000000000011350  4489442420                mov      dword ptr [rsp + 0x20], r8d
  0000000000011355  4c8bc7                    mov      r8, rdi
  0000000000011358  498bca                    mov      rcx, r10
  000000000001135B  e830090000                call     0x11c90
  0000000000011360  e917030000                jmp      0x1167c
  0000000000011365  4489442420                mov      dword ptr [rsp + 0x20], r8d
  000000000001136A  4c8bc7                    mov      r8, rdi
  000000000001136D  498bca                    mov      rcx, r10
  0000000000011370  e88b090000                call     0x11d00
  0000000000011375  e902030000                jmp      0x1167c
  000000000001137A  4489442420                mov      dword ptr [rsp + 0x20], r8d
  000000000001137F  4c8bc7                    mov      r8, rdi
  0000000000011382  498bca                    mov      rcx, r10
  0000000000011385  e886090000                call     0x11d10
  000000000001138A  e9ed020000                jmp      0x1167c
  000000000001138F  4489442420                mov      dword ptr [rsp + 0x20], r8d
  0000000000011394  4c8bc7                    mov      r8, rdi
  0000000000011397  498bca                    mov      rcx, r10
  000000000001139A  e8d1090000                call     0x11d70
  000000000001139F  e9d8020000                jmp      0x1167c
  00000000000113A4  4489442420                mov      dword ptr [rsp + 0x20], r8d
  00000000000113A9  4c8bc7                    mov      r8, rdi
  00000000000113AC  498bca                    mov      rcx, r10
  00000000000113AF  e8dc0a0000                call     0x11e90
  00000000000113B4  e9c3020000                jmp      0x1167c
  00000000000113B9  4489442428                mov      dword ptr [rsp + 0x28], r8d
  00000000000113BE  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  00000000000113C3  4c8bcf                    mov      r9, rdi
  00000000000113C6  4c8bc2                    mov      r8, rdx
  00000000000113C9  498bd2                    mov      rdx, r10
  00000000000113CC  b901000000                mov      ecx, 1
  00000000000113D1  e80a0b0000                call     0x11ee0
  00000000000113D6  e9a1020000                jmp      0x1167c
  00000000000113DB  4489442428                mov      dword ptr [rsp + 0x28], r8d
  00000000000113E0  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  00000000000113E5  4c8bcf                    mov      r9, rdi
  00000000000113E8  4c8bc2                    mov      r8, rdx
  00000000000113EB  498bd2                    mov      rdx, r10
  00000000000113EE  b901000000                mov      ecx, 1
  00000000000113F3  e8380b0000                call     0x11f30
  00000000000113F8  e97f020000                jmp      0x1167c
  00000000000113FD  4489442428                mov      dword ptr [rsp + 0x28], r8d
  0000000000011402  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  0000000000011407  4c8bcf                    mov      r9, rdi
  000000000001140A  4c8bc2                    mov      r8, rdx
  000000000001140D  498bd2                    mov      rdx, r10
  0000000000011410  b902000000                mov      ecx, 2
  0000000000011415  e8c60a0000                call     0x11ee0
  000000000001141A  e95d020000                jmp      0x1167c
  000000000001141F  4489442428                mov      dword ptr [rsp + 0x28], r8d
  0000000000011424  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  0000000000011429  4c8bcf                    mov      r9, rdi
  000000000001142C  4c8bc2                    mov      r8, rdx
  000000000001142F  498bd2                    mov      rdx, r10
  0000000000011432  b902000000                mov      ecx, 2
  0000000000011437  e8f40a0000                call     0x11f30
  000000000001143C  e93b020000                jmp      0x1167c
  0000000000011441  4489442428                mov      dword ptr [rsp + 0x28], r8d
  0000000000011446  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  000000000001144B  4c8bcf                    mov      r9, rdi
  000000000001144E  4c8bc2                    mov      r8, rdx
  0000000000011451  498bd2                    mov      rdx, r10
  0000000000011454  b904000000                mov      ecx, 4
  0000000000011459  e8820a0000                call     0x11ee0
  000000000001145E  e919020000                jmp      0x1167c
  0000000000011463  4489442428                mov      dword ptr [rsp + 0x28], r8d
  0000000000011468  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  000000000001146D  4c8bcf                    mov      r9, rdi
  0000000000011470  4c8bc2                    mov      r8, rdx
  0000000000011473  498bd2                    mov      rdx, r10
  0000000000011476  b904000000                mov      ecx, 4
  000000000001147B  e8b00a0000                call     0x11f30
  0000000000011480  e9f7010000                jmp      0x1167c
  0000000000011485  4489442428                mov      dword ptr [rsp + 0x28], r8d
  000000000001148A  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  000000000001148F  4c8bcf                    mov      r9, rdi
  0000000000011492  4c8bc2                    mov      r8, rdx
  0000000000011495  498bd2                    mov      rdx, r10
  0000000000011498  b901000000                mov      ecx, 1
  000000000001149D  e8ce0a0000                call     0x11f70
  00000000000114A2  e9d5010000                jmp      0x1167c
  00000000000114A7  4489442428                mov      dword ptr [rsp + 0x28], r8d
  00000000000114AC  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  00000000000114B1  4c8bcf                    mov      r9, rdi
  00000000000114B4  4c8bc2                    mov      r8, rdx
  00000000000114B7  498bd2                    mov      rdx, r10
  00000000000114BA  b902000000                mov      ecx, 2
  00000000000114BF  e8ac0a0000                call     0x11f70
  00000000000114C4  e9b3010000                jmp      0x1167c
  00000000000114C9  4489442428                mov      dword ptr [rsp + 0x28], r8d
  00000000000114CE  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  00000000000114D3  4c8bcf                    mov      r9, rdi
  00000000000114D6  4c8bc2                    mov      r8, rdx
  00000000000114D9  498bd2                    mov      rdx, r10
  00000000000114DC  b904000000                mov      ecx, 4
  00000000000114E1  e88a0a0000                call     0x11f70
  00000000000114E6  e991010000                jmp      0x1167c
  00000000000114EB  4489442428                mov      dword ptr [rsp + 0x28], r8d
  00000000000114F0  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  00000000000114F5  4c8bcf                    mov      r9, rdi
  00000000000114F8  4c8bc2                    mov      r8, rdx
  00000000000114FB  498bd2                    mov      rdx, r10
  00000000000114FE  b901000000                mov      ecx, 1
  0000000000011503  e8e80a0000                call     0x11ff0
  0000000000011508  e96f010000                jmp      0x1167c
  000000000001150D  4489442428                mov      dword ptr [rsp + 0x28], r8d
  0000000000011512  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  0000000000011517  4c8bcf                    mov      r9, rdi
  000000000001151A  4c8bc2                    mov      r8, rdx
  000000000001151D  498bd2                    mov      rdx, r10
  0000000000011520  b902000000                mov      ecx, 2
  0000000000011525  e8c60a0000                call     0x11ff0
  000000000001152A  e94d010000                jmp      0x1167c
  000000000001152F  4489442428                mov      dword ptr [rsp + 0x28], r8d
  0000000000011534  44894c2420                mov      dword ptr [rsp + 0x20], r9d
  0000000000011539  4c8bcf                    mov      r9, rdi
  000000000001153C  4c8bc2                    mov      r8, rdx
  000000000001153F  498bd2                    mov      rdx, r10
  0000000000011542  b904000000                mov      ecx, 4
  0000000000011547  e8a40a0000                call     0x11ff0
  000000000001154C  e92b010000                jmp      0x1167c
  0000000000011551  4489442420                mov      dword ptr [rsp + 0x20], r8d
  0000000000011556  4c8bc7                    mov      r8, rdi
  0000000000011559  498bca                    mov      rcx, r10
  000000000001155C  e8cf0c0000                call     0x12230
  0000000000011561  e916010000                jmp      0x1167c
  0000000000011566  4489442420                mov      dword ptr [rsp + 0x20], r8d
  000000000001156B  4c8bc7                    mov      r8, rdi
  000000000001156E  498bca                    mov      rcx, r10
  0000000000011571  e8da0a0000                call     0x12050
  0000000000011576  e901010000                jmp      0x1167c
  000000000001157B  4489442420                mov      dword ptr [rsp + 0x20], r8d
  0000000000011580  4c8bc7                    mov      r8, rdi
  0000000000011583  498bca                    mov      rcx, r10
  0000000000011586  e8e50a0000                call     0x12070
  000000000001158B  e9ec000000                jmp      0x1167c
  0000000000011590  4489442420                mov      dword ptr [rsp + 0x20], r8d
  0000000000011595  4c8bc7                    mov      r8, rdi
  0000000000011598  498bca                    mov      rcx, r10
  000000000001159B  e890100000                call     0x12630
  00000000000115A0  e9d7000000                jmp      0x1167c
  00000000000115A5  4489442420                mov      dword ptr [rsp + 0x20], r8d
  00000000000115AA  4c8bc7                    mov      r8, rdi
  00000000000115AD  498bca                    mov      rcx, r10
  00000000000115B0  e87b100000                call     0x12630
  00000000000115B5  e9c2000000                jmp      0x1167c
  00000000000115BA  4489442420                mov      dword ptr [rsp + 0x20], r8d
  00000000000115BF  4c8bc7                    mov      r8, rdi
  00000000000115C2  498bca                    mov      rcx, r10

; ... (58 more lines)

; === Port IN handler (inline, leaf function) ===
; ecx = size (1=byte, 2=word, 4=dword)
; [rdx] = port number (u16)
; Output: [r8] = read value, [r9+0x38] = 4 (bytes returned)
  0000000000011EE0  4c8bc2                    mov      r8, rdx
  0000000000011EE3  418b10                    mov      edx, dword ptr [r8]
  0000000000011EE6  83e901                    sub      ecx, 1
  0000000000011EE9  742c                      je       0x11f17
  0000000000011EEB  83e901                    sub      ecx, 1
  0000000000011EEE  7414                      je       0x11f04
  0000000000011EF0  83e902                    sub      ecx, 2
  0000000000011EF3  7529                      jne      0x11f1e
  0000000000011EF5  ed                        in       eax, dx  ; <<< PRIVILEGED >>>
  0000000000011EF6  418900                    mov      dword ptr [r8], eax
  0000000000011EF9  49c7413804000000          mov      qword ptr [r9 + 0x38], 4
  0000000000011F01  33c0                      xor      eax, eax
  0000000000011F03  c3                        ret      
  0000000000011F04  66ed                      in       ax, dx  ; <<< PRIVILEGED >>>
  0000000000011F06  0fb7c0                    movzx    eax, ax
  0000000000011F09  418900                    mov      dword ptr [r8], eax
  0000000000011F0C  49c7413804000000          mov      qword ptr [r9 + 0x38], 4
  0000000000011F14  33c0                      xor      eax, eax
  0000000000011F16  c3                        ret      
  0000000000011F17  ec                        in       al, dx  ; <<< PRIVILEGED >>>
  0000000000011F18  0fb6c0                    movzx    eax, al
  0000000000011F1B  418900                    mov      dword ptr [r8], eax
  0000000000011F1E  49c7413804000000          mov      qword ptr [r9 + 0x38], 4
  0000000000011F26  33c0                      xor      eax, eax
  0000000000011F28  c3                        ret      
  0000000000011F29  cc                        int3     
  0000000000011F2A  cc                        int3     
  0000000000011F2B  cc                        int3     
  0000000000011F2C  cc                        int3     
  0000000000011F2D  cc                        int3     
  0000000000011F2E  cc                        int3     
  0000000000011F2F  cc                        int3     

; === Port OUT handler (inline, leaf function) ===
; ecx = size, [rdx] = port:u16, [rdx+4] = value:u32
  0000000000011F30  448b12                    mov      r10d, dword ptr [rdx]
  0000000000011F33  8b4204                    mov      eax, dword ptr [rdx + 4]
  0000000000011F36  49c7413800000000          mov      qword ptr [r9 + 0x38], 0
  0000000000011F3E  83e901                    sub      ecx, 1
  0000000000011F41  741b                      je       0x11f5e
  0000000000011F43  83e901                    sub      ecx, 1
  0000000000011F46  740d                      je       0x11f55
  0000000000011F48  83e902                    sub      ecx, 2
  0000000000011F4B  7516                      jne      0x11f63
  0000000000011F4D  410fb7d2                  movzx    edx, r10w
  0000000000011F51  ef                        out      dx, eax  ; <<< PRIVILEGED >>>
  0000000000011F52  33c0                      xor      eax, eax
  0000000000011F54  c3                        ret      
  0000000000011F55  410fb7d2                  movzx    edx, r10w
  0000000000011F59  66ef                      out      dx, ax  ; <<< PRIVILEGED >>>
  0000000000011F5B  33c0                      xor      eax, eax
  0000000000011F5D  c3                        ret      
  0000000000011F5E  410fb7d2                  movzx    edx, r10w
  0000000000011F62  ee                        out      dx, al  ; <<< PRIVILEGED >>>
  0000000000011F63  33c0                      xor      eax, eax
  0000000000011F65  c3                        ret      
  0000000000011F66  cc                        int3     
  0000000000011F67  cc                        int3     
  0000000000011F68  cc                        int3     
  0000000000011F69  cc                        int3     
  0000000000011F6A  cc                        int3     
  0000000000011F6B  cc                        int3     
  0000000000011F6C  cc                        int3     
  0000000000011F6D  cc                        int3     
  0000000000011F6E  cc                        int3     
  0000000000011F6F  cc                        int3     

; === MSR READ handler (inline, leaf function) ===
; [r9] = MSR index (u32), output: [r9] = value (u64)
  0000000000012460  4c8bc9                    mov      r9, rcx
  0000000000012463  418b09                    mov      ecx, dword ptr [r9]
  0000000000012466  0f32                      rdmsr      ; <<< PRIVILEGED >>>
  0000000000012468  48c1e220                  shl      rdx, 0x20
  000000000001246C  480bd0                    or       rdx, rax
  000000000001246F  498911                    mov      qword ptr [r9], rdx
  0000000000012472  49c7403808000000          mov      qword ptr [r8 + 0x38], 8
  000000000001247A  33c0                      xor      eax, eax
  000000000001247C  c3                        ret      

; === Physical Memory Map handler ===
  0000000000011AE0  53                        push     rbx
  0000000000011AE1  57                        push     rdi
  0000000000011AE2  4883ec28                  sub      rsp, 0x28
  0000000000011AE6  498bf8                    mov      rdi, r8
  0000000000011AE9  488bc2                    mov      rax, rdx
  0000000000011AEC  488bd9                    mov      rbx, rcx
  0000000000011AEF  488d90a8000000            lea      rdx, [rax + 0xa8]
  0000000000011AF6  488d88a0000000            lea      rcx, [rax + 0xa0]
  0000000000011AFD  4c8bc3                    mov      r8, rbx
  0000000000011B00  e8bb0e0000                call     0x129c0
  0000000000011B05  488b4018                  mov      rax, qword ptr [rax + 0x18]
  0000000000011B09  4885c0                    test     rax, rax
  0000000000011B0C  7517                      jne      0x11b25
  0000000000011B0E  488bcb                    mov      rcx, rbx
  0000000000011B11  e8ca0f0000                call     0x12ae0
  0000000000011B16  48c7473804000000          mov      qword ptr [rdi + 0x38], 4
  0000000000011B1E  4883c428                  add      rsp, 0x28
  0000000000011B22  5f                        pop      rdi
  0000000000011B23  5b                        pop      rbx
  0000000000011B24  c3                        ret      
  0000000000011B25  488903                    mov      qword ptr [rbx], rax
  0000000000011B28  33c0                      xor      eax, eax
  0000000000011B2A  48c7473804000000          mov      qword ptr [rdi + 0x38], 4
  0000000000011B32  4883c428                  add      rsp, 0x28
  0000000000011B36  5f                        pop      rdi
  0000000000011B37  5b                        pop      rbx
  0000000000011B38  c3                        ret      

; === Physical Memory Map core (ZwOpenSection + ZwMapViewOfSection) ===
  0000000000012AE0  53                        push     rbx
  0000000000012AE1  56                        push     rsi
  0000000000012AE2  57                        push     rdi
  0000000000012AE3  4154                      push     r12
  0000000000012AE5  4155                      push     r13
  0000000000012AE7  4156                      push     r14
  0000000000012AE9  4881ece8000000            sub      rsp, 0xe8
  0000000000012AF0  488bf1                    mov      rsi, rcx
  0000000000012AF3  4533f6                    xor      r14d, r14d
  0000000000012AF6  4c89742460                mov      qword ptr [rsp + 0x60], r14
  0000000000012AFB  4c89b42488000000          mov      qword ptr [rsp + 0x88], r14
  0000000000012B03  448b26                    mov      r12d, dword ptr [rsi]
  0000000000012B06  448b6e04                  mov      r13d, dword ptr [rsi + 4]
  0000000000012B0A  488b5e08                  mov      rbx, qword ptr [rsi + 8]
  0000000000012B0E  8b4610                    mov      eax, dword ptr [rsi + 0x10]
  0000000000012B11  89442478                  mov      dword ptr [rsp + 0x78], eax
  0000000000012B15  89442454                  mov      dword ptr [rsp + 0x54], eax
  0000000000012B19  8b4614                    mov      eax, dword ptr [rsi + 0x14]
  0000000000012B1C  89442450                  mov      dword ptr [rsp + 0x50], eax
  0000000000012B20  488d15d9010000            lea      rdx, [rip + 0x1d9]
  0000000000012B27  488d8c24c8000000          lea      rcx, [rsp + 0xc8]
  0000000000012B2F  ff15f3040000              call     qword ptr [rip + 0x4f3]  ; RtlInitUnicodeString
  0000000000012B35  c784249800000030000000    mov      dword ptr [rsp + 0x98], 0x30
  0000000000012B40  4c89b424a0000000          mov      qword ptr [rsp + 0xa0], r14
  0000000000012B48  c78424b000000040000000    mov      dword ptr [rsp + 0xb0], 0x40
  0000000000012B53  488d8424c8000000          lea      rax, [rsp + 0xc8]
  0000000000012B5B  48898424a8000000          mov      qword ptr [rsp + 0xa8], rax
  0000000000012B63  4c89b424b8000000          mov      qword ptr [rsp + 0xb8], r14
  0000000000012B6B  4c89b424c0000000          mov      qword ptr [rsp + 0xc0], r14
  0000000000012B73  4c8d842498000000          lea      r8, [rsp + 0x98]
  0000000000012B7B  bf1f000f00                mov      edi, 0xf001f
  0000000000012B80  8bd7                      mov      edx, edi
  0000000000012B82  488d4c2460                lea      rcx, [rsp + 0x60]
  0000000000012B87  ff154b050000              call     qword ptr [rip + 0x54b]  ; ZwOpenSection
  0000000000012B8D  85c0                      test     eax, eax
  0000000000012B8F  0f8c55010000              jl       0x12cea
  0000000000012B95  4c89742428                mov      qword ptr [rsp + 0x28], r14
  0000000000012B9A  488d842488000000          lea      rax, [rsp + 0x88]
  0000000000012BA2  4889442420                mov      qword ptr [rsp + 0x20], rax
  0000000000012BA7  4532c9                    xor      r9b, r9b
  0000000000012BAA  4533c0                    xor      r8d, r8d
  0000000000012BAD  8bd7                      mov      edx, edi
  0000000000012BAF  488b4c2460                mov      rcx, qword ptr [rsp + 0x60]
  0000000000012BB4  ff1516050000              call     qword ptr [rip + 0x516]  ; ObReferenceObjectByHandle
  0000000000012BBA  8bf8                      mov      edi, eax
  0000000000012BBC  85ff                      test     edi, edi
  0000000000012BBE  0f8c19010000              jl       0x12cdd
  0000000000012BC4  8b442450                  mov      eax, dword ptr [rsp + 0x50]
  0000000000012BC8  4803c3                    add      rax, rbx
  0000000000012BCB  4889442468                mov      qword ptr [rsp + 0x68], rax
  0000000000012BD0  488d442470                lea      rax, [rsp + 0x70]
  0000000000012BD5  4889442420                mov      qword ptr [rsp + 0x20], rax
  0000000000012BDA  4c8d4c2454                lea      r9, [rsp + 0x54]
  0000000000012BDF  4c8bc3                    mov      r8, rbx
  0000000000012BE2  418bd5                    mov      edx, r13d
  0000000000012BE5  418bcc                    mov      ecx, r12d
  0000000000012BE8  ff1522040000              call     qword ptr [rip + 0x422]  ; HalTranslateBusAddress
  0000000000012BEE  0fb6d8                    movzx    ebx, al
  0000000000012BF1  488d442468                lea      rax, [rsp + 0x68]
  0000000000012BF6  4889442420                mov      qword ptr [rsp + 0x20], rax
  0000000000012BFB  4c8d4c2478                lea      r9, [rsp + 0x78]
  0000000000012C00  4c8b442468                mov      r8, qword ptr [rsp + 0x68]
  0000000000012C05  418bd5                    mov      edx, r13d
  0000000000012C08  418bcc                    mov      ecx, r12d
  0000000000012C0B  ff15ff030000              call     qword ptr [rip + 0x3ff]  ; HalTranslateBusAddress
  0000000000012C11  84db                      test     bl, bl
  0000000000012C13  0f84bf000000              je       0x12cd8
  0000000000012C19  84c0                      test     al, al
  0000000000012C1B  0f84b7000000              je       0x12cd8
  0000000000012C21  488b4c2468                mov      rcx, qword ptr [rsp + 0x68]
  0000000000012C26  488b442470                mov      rax, qword ptr [rsp + 0x70]
  0000000000012C2B  482bc8                    sub      rcx, rax
  0000000000012C2E  48898c2490000000          mov      qword ptr [rsp + 0x90], rcx
  0000000000012C36  85c9                      test     ecx, ecx
  0000000000012C38  0f849a000000              je       0x12cd8
  0000000000012C3E  894c2450                  mov      dword ptr [rsp + 0x50], ecx
  0000000000012C42  4439742454                cmp      dword ptr [rsp + 0x54], r14d
  0000000000012C47  740e                      je       0x12c57
  0000000000012C49  8b442470                  mov      eax, dword ptr [rsp + 0x70]
  0000000000012C4D  8906                      mov      dword ptr [rsi], eax
