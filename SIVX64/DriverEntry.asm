; SIVX64.sys DriverEntry
; RVA: 0x32cd4

0x42CD4: mov      rax, qword ptr [rip - 0x23bdb]  ; → L"ꈲ⷟⮙"
0x42CDB: movabs   r9, 0x2b992ddfa232
0x42CE5: test     rax, rax
0x42CE8: je       0x42cef
0x42CEA: cmp      rax, r9
0x42CED: jne      0x42d1e
0x42CEF: lea      r8, [rip - 0x23bf6]  ; → L"ꈲ⷟⮙"
0x42CF6: movabs   rax, 0xfffff78000000320
0x42D00: mov      rax, qword ptr [rax]
0x42D03: xor      rax, r8
0x42D06: movabs   r8, 0xffffffffffff
0x42D10: and      rax, r8
0x42D13: cmove    rax, r9
0x42D17: mov      qword ptr [rip - 0x23c1e], rax  ; → L"ꈲ⷟⮙"
0x42D1E: not      rax
0x42D21: mov      qword ptr [rip - 0x23c20], rax  ; → L"巍툠푦￿勨"
0x42D28: jmp      0x42008
0x42D2D: int3     
