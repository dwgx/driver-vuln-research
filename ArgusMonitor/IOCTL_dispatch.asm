; ArgusMonitor.sys IRP_MJ_DEVICE_CONTROL handler disassembly
; Handler RVA: 0x1030
; Handler Size: 10144 bytes
; IOCTL codes found: 65
;
; Known IOCTLs:
;   0x9c40300c = UNKNOWN_IOCTL_9C40300C @ 0x1400010aa
;   0x9c4025f4 = UNKNOWN_IOCTL_9C4025F4 @ 0x1400010bd
;   0x9c40238c = UNKNOWN_IOCTL_9C40238C @ 0x1400010d0
;   0x9c40207c = UNKNOWN_IOCTL_9C40207C @ 0x1400010e3
;   0x9c4020b4 = UNKNOWN_IOCTL_9C4020B4 @ 0x1400010ee
;   0x9c4020d8 = IOCTL_PHYSMEM_RD_DW @ 0x1400010f9
;   0x9c4020ec = UNKNOWN_IOCTL_9C4020EC @ 0x140001104
;   0x9c4020f4 = IOCTL_MSR_READ_1 @ 0x14000110f
;   0x9c402264 = UNKNOWN_IOCTL_9C402264 @ 0x14000111a
;   0x9c402334 = UNKNOWN_IOCTL_9C402334 @ 0x140001125
;   0x9c40240c = UNKNOWN_IOCTL_9C40240C @ 0x1400016a1
;   0x9c402490 = IOCTL_PORT_OUT_DWORD @ 0x1400016ac
;   0x9c4024b8 = UNKNOWN_IOCTL_9C4024B8 @ 0x1400016b7
;   0x9c4024e8 = IOCTL_MSR_WRITE_1 @ 0x1400016c2
;   0x9c402510 = IOCTL_PHYSMEM_WR_BYTE @ 0x1400016cd
;   0x9c4025e4 = UNKNOWN_IOCTL_9C4025E4 @ 0x1400016d8
;   0x9c403e10 = UNKNOWN_IOCTL_9C403E10 @ 0x140001840
;   0x9c402b30 = UNKNOWN_IOCTL_9C402B30 @ 0x140001ad9
;   0x9c4026f0 = UNKNOWN_IOCTL_9C4026F0 @ 0x140001aec
;   0x9c402724 = IOCTL_PCI_CONFIG @ 0x140001af7
;   0x9c40277c = IOCTL_PORT_OUT_BYTE @ 0x140001b02
;   0x9c4027b8 = UNKNOWN_IOCTL_9C4027B8 @ 0x140001b0d
;   0x9c40290c = UNKNOWN_IOCTL_9C40290C @ 0x140001b18
;   0x9c402934 = IOCTL_PHYSMEM_UNMAP @ 0x140001b23
;   0x9c402994 = IOCTL_PHYSMEM_SINGLE @ 0x140001b2e
;   0x9c402b60 = UNKNOWN_IOCTL_9C402B60 @ 0x140001e7e
;   0x9c402b74 = IOCTL_HANDSHAKE @ 0x140001e89
;   0x9c402c74 = UNKNOWN_IOCTL_9C402C74 @ 0x140001e94
;   0x9c402d20 = UNKNOWN_IOCTL_9C402D20 @ 0x140001e9f
;   0x9c402e00 = IOCTL_PORT_IN_DWORD @ 0x140001eaa
;   0x9c402e94 = IOCTL_PHYSMEM_RD_BYTE @ 0x140001eb5
;   0x9c403a54 = IOCTL_PHYSMEM_MAP @ 0x140002592
;   0x9c403424 = UNKNOWN_IOCTL_9C403424 @ 0x1400025a5
;   0x9c403100 = UNKNOWN_IOCTL_9C403100 @ 0x1400025b8
;   0x9c403124 = UNKNOWN_IOCTL_9C403124 @ 0x1400025c3
;   0x9c403134 = UNKNOWN_IOCTL_9C403134 @ 0x1400025ce
;   0x9c403144 = UNKNOWN_IOCTL_9C403144 @ 0x1400025d9
;   0x9c403218 = IOCTL_PHYSMEM_RMR @ 0x1400025e4
;   0x9c4032cc = UNKNOWN_IOCTL_9C4032CC @ 0x1400025ef
;   0x9c40340c = UNKNOWN_IOCTL_9C40340C @ 0x1400025fa
;   0x9c4034b8 = UNKNOWN_IOCTL_9C4034B8 @ 0x140002b00
;   0x9c4035bc = UNKNOWN_IOCTL_9C4035BC @ 0x140002b0b
;   0x9c4036fc = UNKNOWN_IOCTL_9C4036FC @ 0x140002b16
;   0x9c403724 = UNKNOWN_IOCTL_9C403724 @ 0x140002b1d
;   0x9c403894 = UNKNOWN_IOCTL_9C403894 @ 0x140002b28
;   0x9c40391c = UNKNOWN_IOCTL_9C40391C @ 0x140002b33
;   0x9c4024b8 = UNKNOWN_IOCTL_9C4024B8 @ 0x140002c20
;   0x9c4036fc = UNKNOWN_IOCTL_9C4036FC @ 0x140002d6b
;   0x9c403d74 = UNKNOWN_IOCTL_9C403D74 @ 0x140002f46
;   0x9c403a88 = IOCTL_PORT_IN_BYTE @ 0x140002f57
;   0x9c403ab0 = UNKNOWN_IOCTL_9C403AB0 @ 0x140002f62
;   0x9c403ad0 = UNKNOWN_IOCTL_9C403AD0 @ 0x140002f6d
;   0x9c403c88 = UNKNOWN_IOCTL_9C403C88 @ 0x140002f78
;   0x9c403d14 = UNKNOWN_IOCTL_9C403D14 @ 0x140002f83
;   0x9c403d3c = IOCTL_PHYSMEM_WR_DW @ 0x140002f8a
;   0x9c4020f4 = IOCTL_MSR_READ_1 @ 0x140003247
;   0x9c403d74 = UNKNOWN_IOCTL_9C403D74 @ 0x140003261
;   0x9c4020f4 = IOCTL_MSR_READ_1 @ 0x1400032fb
;   0x9c403d74 = UNKNOWN_IOCTL_9C403D74 @ 0x14000330b
;   0x9c403dac = UNKNOWN_IOCTL_9C403DAC @ 0x1400033bf
;   0x9c403de0 = UNKNOWN_IOCTL_9C403DE0 @ 0x1400033ca
;   0x9c403e10 = UNKNOWN_IOCTL_9C403E10 @ 0x1400033d5
;   0x9c403fe0 = UNKNOWN_IOCTL_9C403FE0 @ 0x1400033e4
;   0x9c40f292 = UNKNOWN_IOCTL_9C40F292 @ 0x1400033ef
;   0x9c40f852 = UNKNOWN_IOCTL_9C40F852 @ 0x1400033fa
;
; Import calls in handler:
;   0x140001483: CALL ntoskrnl.exe!RtlInitUnicodeString
;   0x1400024f9: CALL ntoskrnl.exe!RtlInitUnicodeString
;   0x14000282d: CALL ntoskrnl.exe!RtlInitUnicodeString
;   0x140003773: CALL ntoskrnl.exe!KeSetEvent
;   0x14000378c: CALL ntoskrnl.exe!KeSetEvent
;   0x14000379b: CALL ntoskrnl.exe!IofCompleteRequest
;
; --- Disassembly (first 200 instructions) ---
;
  0000000140001030  48895c2408                mov qword ptr [rsp + 8], rbx
  0000000140001035  4889742418                mov qword ptr [rsp + 0x18], rsi
  000000014000103A  57                        push rdi
  000000014000103B  4154                      push r12
  000000014000103D  4155                      push r13
  000000014000103F  4156                      push r14
  0000000140001041  4157                      push r15
  0000000140001043  4881ec30030000            sub rsp, 0x330
  000000014000104A  488b056fd60000            mov rax, qword ptr [rip + 0xd66f]
  0000000140001051  4833c4                    xor rax, rsp
  0000000140001054  4889842420030000          mov qword ptr [rsp + 0x320], rax
  000000014000105C  4c8bea                    mov r13, rdx
  000000014000105F  4889942498000000          mov qword ptr [rsp + 0x98], rdx
  0000000140001067  4533ff                    xor r15d, r15d
  000000014000106A  418bf7                    mov esi, r15d
  000000014000106D  4489bc2480000000          mov dword ptr [rsp + 0x80], r15d
  0000000140001075  44897c2454                mov dword ptr [rsp + 0x54], r15d
  000000014000107A  44897c2470                mov dword ptr [rsp + 0x70], r15d
  000000014000107F  488b82b8000000            mov rax, qword ptr [rdx + 0xb8]
  0000000140001086  4889842488000000          mov qword ptr [rsp + 0x88], rax
  000000014000108E  8b5810                    mov ebx, dword ptr [rax + 0x10]
  0000000140001091  8b7808                    mov edi, dword ptr [rax + 8]
  0000000140001094  89bc2484000000            mov dword ptr [rsp + 0x84], edi
  000000014000109B  4c8b7218                  mov r14, qword ptr [rdx + 0x18]
  000000014000109F  4c89b424a0000000          mov qword ptr [rsp + 0xa0], r14
  00000001400010A7  8b4018                    mov eax, dword ptr [rax + 0x18]
  00000001400010AA  b90c30409c                mov ecx, 0x9c40300c
  00000001400010AF  3bc1                      cmp eax, ecx
  00000001400010B1  0f87db140000              ja 0x140002592
  00000001400010B7  0f8468140000              je 0x140002525
  00000001400010BD  b9f425409c                mov ecx, 0x9c4025f4
  00000001400010C2  3bc1                      cmp eax, ecx
  00000001400010C4  0f870f0a0000              ja 0x140001ad9
  00000001400010CA  0f8479090000              je 0x140001a49
  00000001400010D0  b98c23409c                mov ecx, 0x9c40238c
  00000001400010D5  3bc1                      cmp eax, ecx
  00000001400010D7  0f87c4050000              ja 0x1400016a1
  00000001400010DD  0f84dd040000              je 0x1400015c0
  00000001400010E3  3d7c20409c                cmp eax, 0x9c40207c
  00000001400010E8  0f84ed030000              je 0x1400014db
  00000001400010EE  3db420409c                cmp eax, 0x9c4020b4
  00000001400010F3  0f840f030000              je 0x140001408
  00000001400010F9  3dd820409c                cmp eax, 0x9c4020d8
  00000001400010FE  0f8480020000              je 0x140001384
  0000000140001104  3dec20409c                cmp eax, 0x9c4020ec
  0000000140001109  0f8415020000              je 0x140001324
  000000014000110F  3df420409c                cmp eax, 0x9c4020f4
  0000000140001114  0f8434210000              je 0x14000324e
  000000014000111A  3d6422409c                cmp eax, 0x9c402264
  000000014000111F  0f84cb000000              je 0x1400011f0
  0000000140001125  3d3423409c                cmp eax, 0x9c402334
  000000014000112A  0f85d1220000              jne 0x140003401
  0000000140001130  83fb20                    cmp ebx, 0x20
  0000000140001133  0f850b260000              jne 0x140003744
  0000000140001139  83ff70                    cmp edi, 0x70
  000000014000113C  0f8502260000              jne 0x140003744
  0000000140001142  803df3df000001            cmp byte ptr [rip + 0xdff3], 1
  0000000140001149  740a                      je 0x140001155
  000000014000114B  be08a000e0                mov esi, 0xe000a008
  0000000140001150  e9f4250000                jmp 0x140003749
  0000000140001155  41b001                    mov r8b, 1
  0000000140001158  ba20000000                mov edx, 0x20
  000000014000115D  498bce                    mov rcx, r14
  0000000140001160  e8d3270000                call 0x140003938
  0000000140001165  84c0                      test al, al
  0000000140001167  750a                      jne 0x140001173
  0000000140001169  be09a000e0                mov esi, 0xe000a009
  000000014000116E  e9d6250000                jmp 0x140003749
  0000000140001173  41b001                    mov r8b, 1
  0000000140001176  488d542454                lea rdx, [rsp + 0x54]
  000000014000117B  488d0d9edf0000            lea rcx, [rip + 0xdf9e]
  0000000140001182  e86d270000                call 0x1400038f4
  0000000140001187  85c0                      test eax, eax
  0000000140001189  740a                      je 0x140001195
  000000014000118B  be03a000e0                mov esi, 0xe000a003
  0000000140001190  e9b4250000                jmp 0x140003749
  0000000140001195  418b06                    mov eax, dword ptr [r14]
  0000000140001198  89442458                  mov dword ptr [rsp + 0x58], eax
  000000014000119C  418b4604                  mov eax, dword ptr [r14 + 4]
  00000001400011A0  8944245c                  mov dword ptr [rsp + 0x5c], eax
  00000001400011A4  418b5e08                  mov ebx, dword ptr [r14 + 8]
  00000001400011A8  895c2464                  mov dword ptr [rsp + 0x64], ebx
  00000001400011AC  33d2                      xor edx, edx
  00000001400011AE  448d4270                  lea r8d, [rdx + 0x70]
  00000001400011B2  498bce                    mov rcx, r14
  00000001400011B5  e806b80000                call 0x14000c9c0
  00000001400011BA  4d8bce                    mov r9, r14
  00000001400011BD  448bc3                    mov r8d, ebx
  00000001400011C0  8b54245c                  mov edx, dword ptr [rsp + 0x5c]
  00000001400011C4  8b4c2458                  mov ecx, dword ptr [rsp + 0x58]
  00000001400011C8  e8e78e0000                call 0x14000a0b4
  00000001400011CD  8bf0                      mov esi, eax
  00000001400011CF  89442450                  mov dword ptr [rsp + 0x50], eax
  00000001400011D3  41b001                    mov r8b, 1
  00000001400011D6  ba70000000                mov edx, 0x70
  00000001400011DB  498bce                    mov rcx, r14
  00000001400011DE  e8f9270000                call 0x1400039dc
  00000001400011E3  49c7453870000000          mov qword ptr [r13 + 0x38], 0x70
  00000001400011EB  e95d250000                jmp 0x14000374d
  00000001400011F0  41bc00020000              mov r12d, 0x200
  00000001400011F6  413bdc                    cmp ebx, r12d
  00000001400011F9  0f8545250000              jne 0x140003744
  00000001400011FF  418d5c2410                lea ebx, [r12 + 0x10]
  0000000140001204  3bfb                      cmp edi, ebx
  0000000140001206  0f8538250000              jne 0x140003744
  000000014000120C  803d29df000001            cmp byte ptr [rip + 0xdf29], 1
  0000000140001213  0f8532ffffff              jne 0x14000114b
  0000000140001219  4533c0                    xor r8d, r8d
  000000014000121C  418bd4                    mov edx, r12d
  000000014000121F  498bce                    mov rcx, r14
  0000000140001222  e811270000                call 0x140003938
  0000000140001227  84c0                      test al, al
  0000000140001229  0f843affffff              je 0x140001169
  000000014000122F  41b001                    mov r8b, 1
  0000000140001232  488d542454                lea rdx, [rsp + 0x54]
  0000000140001237  488d0de2de0000            lea rcx, [rip + 0xdee2]
  000000014000123E  e8b1260000                call 0x1400038f4
  0000000140001243  85c0                      test eax, eax
  0000000140001245  0f8540ffffff              jne 0x14000118b
  000000014000124B  418a3e                    mov dil, byte ptr [r14]
  000000014000124E  40887c2474                mov byte ptr [rsp + 0x74], dil
  0000000140001253  4080ff1f                  cmp dil, 0x1f
  0000000140001257  760a                      jbe 0x140001263
  0000000140001259  be0d0000c0                mov esi, 0xc000000d
  000000014000125E  e9e6240000                jmp 0x140003749
  0000000140001263  44887c2460                mov byte ptr [rsp + 0x60], r15b
  0000000140001268  44887c2461                mov byte ptr [rsp + 0x61], r15b
  000000014000126D  488d542461                lea rdx, [rsp + 0x61]
  0000000140001272  488d4c2460                lea rcx, [rsp + 0x60]
  0000000140001277  e8887f0000                call 0x140009204
  000000014000127C  4c8bc3                    mov r8, rbx
  000000014000127F  33d2                      xor edx, edx
  0000000140001281  498bce                    mov rcx, r14
  0000000140001284  e837b70000                call 0x14000c9c0
  0000000140001289  488d0db0de0000            lea rcx, [rip + 0xdeb0]
  0000000140001290  44897c2464                mov dword ptr [rsp + 0x64], r15d
  0000000140001295  453bfc                    cmp r15d, r12d
  0000000140001298  733c                      jae 0x1400012d6
  000000014000129A  418bff                    mov edi, r15d
  000000014000129D  8b040f                    mov eax, dword ptr [rdi + rcx]
  00000001400012A0  89442458                  mov dword ptr [rsp + 0x58], eax
  00000001400012A4  418d4704                  lea eax, [r15 + 4]
  00000001400012A8  8bd8                      mov ebx, eax
  00000001400012AA  8b0408                    mov eax, dword ptr [rax + rcx]
  00000001400012AD  8944245c                  mov dword ptr [rsp + 0x5c], eax
  00000001400012B1  488d54245c                lea rdx, [rsp + 0x5c]
  00000001400012B6  488d4c2458                lea rcx, [rsp + 0x58]
  00000001400012BB  e8fca70000                call 0x14000babc
  00000001400012C0  8b442458                  mov eax, dword ptr [rsp + 0x58]
  00000001400012C4  42890437                  mov dword ptr [rdi + r14], eax
  00000001400012C8  8b44245c                  mov eax, dword ptr [rsp + 0x5c]
  00000001400012CC  42890433                  mov dword ptr [rbx + r14], eax
  00000001400012D0  4183c708                  add r15d, 8
  00000001400012D4  ebb3                      jmp 0x140001289
  00000001400012D6  8a4c2474                  mov cl, byte ptr [rsp + 0x74]
  00000001400012DA  ba01000000                mov edx, 1
  00000001400012DF  d3e2                      shl edx, cl
  00000001400012E1  8b0551de0000              mov eax, dword ptr [rip + 0xde51]
  00000001400012E7  0bc2                      or eax, edx
  00000001400012E9  890549de0000              mov dword ptr [rip + 0xde49], eax
  00000001400012EF  6641c786080200000228      mov word ptr [r14 + 0x208], 0x2802
  00000001400012F9  41c6860a02000002          mov byte ptr [r14 + 0x20a], 2
  0000000140001301  8a442460                  mov al, byte ptr [rsp + 0x60]
  0000000140001305  4188860b020000            mov byte ptr [r14 + 0x20b], al
  000000014000130C  8a442461                  mov al, byte ptr [rsp + 0x61]
  0000000140001310  4188860c020000            mov byte ptr [r14 + 0x20c], al
  0000000140001317  49c7453810020000          mov qword ptr [r13 + 0x38], 0x210
  000000014000131F  e929240000                jmp 0x14000374d
  0000000140001324  85db                      test ebx, ebx
  0000000140001326  0f8518240000              jne 0x140003744
  000000014000132C  448d6318                  lea r12d, [rbx + 0x18]
  0000000140001330  413bfc                    cmp edi, r12d
  0000000140001333  0f850b240000              jne 0x140003744
  0000000140001339  803dfcdd000001            cmp byte ptr [rip + 0xddfc], 1
  0000000140001340  0f8505feffff              jne 0x14000114b
  0000000140001346  41b001                    mov r8b, 1
  0000000140001349  33d2                      xor edx, edx
  000000014000134B  498bce                    mov rcx, r14
  000000014000134E  e8e5250000                call 0x140003938
  0000000140001353  84c0                      test al, al
  0000000140001355  0f840efeffff              je 0x140001169
  000000014000135B  41b001                    mov r8b, 1
  000000014000135E  488d542454                lea rdx, [rsp + 0x54]
  0000000140001363  488d0db6dd0000            lea rcx, [rip + 0xddb6]
  000000014000136A  e885250000                call 0x1400038f4
  000000014000136F  85c0                      test eax, eax
  0000000140001371  0f8514feffff              jne 0x14000118b
  0000000140001377  498bce                    mov rcx, r14
  000000014000137A  e80da90000                call 0x14000bc8c
  000000014000137F  e9a6230000                jmp 0x14000372a
  0000000140001384  41bc18000000              mov r12d, 0x18
  000000014000138A  413bdc                    cmp ebx, r12d
  000000014000138D  0f85b1230000              jne 0x140003744
  0000000140001393  413bfc                    cmp edi, r12d
  0000000140001396  0f85a8230000              jne 0x140003744
  000000014000139C  803d99dd000001            cmp byte ptr [rip + 0xdd99], 1
  00000001400013A3  0f85a2fdffff              jne 0x14000114b
  00000001400013A9  41b001                    mov r8b, 1
  00000001400013AC  418bd4                    mov edx, r12d
  00000001400013AF  498bce                    mov rcx, r14
