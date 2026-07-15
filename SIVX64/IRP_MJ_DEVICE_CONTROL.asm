; SIVX64.sys IOCTL dispatch
; Function: RVA 0x11984 - 0x18ED7

0x21984: mov      r11, rsp
0x21987: mov      qword ptr [r11 + 0x18], rbx
0x2198B: mov      qword ptr [r11 + 0x20], rsi
0x2198F: push     rdi
0x21990: push     r12
0x21992: push     r13
0x21994: push     r14
0x21996: push     r15
0x21998: sub      rsp, 0x520
0x2199F: mov      rax, qword ptr [rip - 0x28a6]  ; → L"ꈲ⷟⮙"
0x219A6: xor      rax, rsp
0x219A9: mov      qword ptr [rsp + 0x510], rax
0x219B1: mov      r15, rdx
0x219B4: mov      qword ptr [rsp + 0x120], rdx
0x219BC: mov      qword ptr [rsp + 0xe8], rdx
0x219C4: xor      esi, esi
0x219C6: mov      qword ptr [r11 - 0x4a0], rsi
0x219CD: mov      rax, qword ptr [rdx + 0xb8]
0x219D4: mov      qword ptr [rsp + 0x130], rax
0x219DC: mov      r12, qword ptr [rcx + 0x40]
0x219E0: mov      qword ptr [rsp + 0x128], r12
0x219E8: mov      qword ptr [rsp + 0xe0], r12
0x219F0: mov      r9, qword ptr [rax + 0x30]
0x219F4: mov      qword ptr [rsp + 0xb8], r9
0x219FC: mov      qword ptr [r11 - 0x440], rsi
0x21A03: mov      r10, qword ptr [r9 + 0x18]
0x21A07: mov      qword ptr [rsp + 0xc0], r10
0x21A0F: mov      qword ptr [r11 - 0x450], 0xfffffffffeced300
0x21A1A: mov      qword ptr [rdx + 0x38], rsi
0x21A1E: mov      dword ptr [rsp + 0x90], 0xc0000004
0x21A29: mov      r14, qword ptr [rdx + 0x18]
0x21A2D: mov      qword ptr [rsp + 0x150], r14
0x21A35: mov      qword ptr [r11 - 0x400], r14
0x21A3C: mov      rcx, r14
0x21A3F: mov      qword ptr [rsp + 0xd0], rcx
0x21A47: mov      qword ptr [r11 - 0x318], rcx
0x21A4E: mov      rdi, r14
0x21A51: mov      qword ptr [r11 - 0x410], r14
0x21A58: mov      qword ptr [r11 - 0x3d0], r14
0x21A5F: mov      ebx, dword ptr [rax + 0x10]
0x21A62: mov      dword ptr [rsp + 0xa0], ebx
0x21A69: mov      dword ptr [rsp + 0xd8], ebx
0x21A70: mov      r13d, dword ptr [rax + 8]
0x21A74: mov      dword ptr [r11 - 0x4b4], r13d
0x21A7B: mov      edx, dword ptr [rax + 0x18]
0x21A7E: mov      dword ptr [rsp + 0xb0], edx
0x21A85: lea      r8d, [rsi + 0x10]
0x21A89: test     byte ptr [r12], r8b
0x21A8D: je       0x21afc
0x21A8F: mov      r9d, edx
0x21A92: shr      r9d, 2
0x21A96: and      r9d, 0xfff
0x21A9D: mov      dword ptr [rsp + 0x40], r13d
0x21AA2: mov      dword ptr [rsp + 0x38], ebx
0x21AA6: mov      qword ptr [rsp + 0x30], r14
0x21AAB: mov      qword ptr [rsp + 0x28], r10
0x21AB0: mov      rax, qword ptr [rsp + 0xb8]
0x21AB8: mov      qword ptr [rsp + 0x20], rax
0x21ABD: lea      r8, [rip + 0x1b14c]  ; → L"剉彐䩍䍟乏剔䱏†┠㌰⁘†漠潦┠⁰漠硦┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠ੵ찀쳌쳌쳌쳌쳌쳌㕖㠮‵䈠極瑬䨠湡ㄠ‴〲㘲愠⁴㠰ㄺ㨶㠴†䑗⁋〶㄰ㄮ〸〰†V쳌쳌쳌쳌㕖㠮5쳌쳌쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†"
0x21AC4: lea      edx, [rsi + 2]
0x21AC7: lea      ecx, [rsi + 0x4d]
0x21ACA: call     qword ptr [rip - 0xc8f0]  ; → DbgPrintEx
0x21AD0: mov      r13d, dword ptr [rsp + 0x94]
0x21AD8: mov      r10, qword ptr [rsp + 0xc0]
0x21AE0: lea      r11d, [rsi + 0x4d]
0x21AE4: mov      edx, dword ptr [rsp + 0xb0]
0x21AEB: lea      r8d, [rsi + 0x10]
0x21AEF: mov      r9, qword ptr [rsp + 0xb8]
0x21AF7: mov      rcx, r14
0x21AFA: jmp      0x21b02
0x21AFC: mov      r11d, 0x4d
0x21B02: mov      eax, 0x100
0x21B07: cmp      edx, eax
0x21B09: ja       0x25722
0x21B0F: cmp      edx, eax
0x21B11: je       0x256d1
0x21B17: cmp      edx, 0x74
0x21B1A: ja       0x23b7b
0x21B20: cmp      edx, 0x74
0x21B23: je       0x23af6
0x21B29: cmp      edx, 0x34
0x21B2C: ja       0x22c32
0x21B32: cmp      edx, 0x34
0x21B35: je       0x22bfa
0x21B3B: mov      eax, 0x18
0x21B40: cmp      edx, eax
0x21B42: ja       0x2281a
0x21B48: cmp      edx, eax
0x21B4A: je       0x2280a
0x21B50: mov      eax, edx
0x21B52: sub      eax, 4
0x21B55: je       0x22753
0x21B5B: sub      eax, 3
0x21B5E: je       0x22723
0x21B64: sub      eax, 1
0x21B67: je       0x225f2
0x21B6D: sub      eax, 4
0x21B70: je       0x224a8
0x21B76: sub      eax, 4
0x21B79: je       0x22164
0x21B7F: sub      eax, 3
0x21B82: je       0x21ec4
0x21B88: cmp      eax, 1
0x21B8B: jne      0x28372
0x21B91: cmp      r13d, ebx
0x21B94: jne      0x28e31
0x21B9A: cmp      ebx, 0x48  ← IOCTL 0x48 (PCI_Read)
0x21B9D: jb       0x28e31
0x21BA3: mov      rdi, qword ptr [r15 + 0x18]
0x21BA7: mov      qword ptr [rsp + 0x128], rdi
0x21BAF: movzx    r14d, word ptr [rdi + 0x14]
0x21BB4: mov      dword ptr [rsp + 0x9c], r14d
0x21BBC: lea      ecx, [r14 + r14*2 + 6]
0x21BC1: shl      ecx, 3
0x21BC4: mov      dword ptr [rsp + 0x98], ecx
0x21BCB: cmp      ecx, ebx
0x21BCD: ja       0x28e31
0x21BD3: cmp      dword ptr [rdi + 8], 0x100
0x21BDA: jb       0x28e31
0x21BE0: cmp      dword ptr [rdi + 8], 0x400000
0x21BE7: ja       0x28e31
0x21BED: mov      rdx, qword ptr [rdi]
0x21BF0: mov      qword ptr [rsp + 0xb8], rdx
0x21BF8: mov      r9b, byte ptr [rdi + 0xe]
0x21BFC: and      r9d, eax
0x21BFF: mov      r8d, dword ptr [rdi + 8]
0x21C03: mov      rcx, r12
0x21C06: call     0x29a50
0x21C0B: mov      r13, rax
0x21C0E: mov      qword ptr [rsp + 0x100], rax
0x21C16: cmp      rax, rsi
0x21C19: je       0x21eb4
0x21C1F: lea      r8, [rdi + 0x30]
0x21C23: mov      qword ptr [rsp + 0x130], r8
0x21C2B: lea      rcx, [r14 + r14*2]
0x21C2F: lea      r10, [r8 + rcx*8]
0x21C33: mov      qword ptr [rsp + 0x2e8], r10
0x21C3B: bt       word ptr [rdi + 0xe], 0xf
0x21C41: jae      0x21d1f
0x21C47: mov      r9d, 0x18
0x21C4D: cmp      r8, r10
0x21C50: jae      0x21db7
0x21C56: mov      edx, dword ptr [r8]
0x21C59: mov      dword ptr [rsp + 0xb0], edx
0x21C60: cmp      edx, dword ptr [rdi + 8]
0x21C63: jae      0x21db7
0x21C69: mov      eax, dword ptr [r8 + 4]
0x21C6D: mov      dword ptr [rsp + 0x98], eax
0x21C74: cmp      eax, 4
0x21C77: ja       0x21db7
0x21C7D: mov      ecx, eax
0x21C7F: shl      rcx, 2
0x21C83: mov      dword ptr [rsp + 0x98], ecx
0x21C8A: bt       word ptr [rdi + 0xe], 0xe
0x21C90: jae      0x21c9b
0x21C92: test     dl, 3
0x21C95: jne      0x21db7
0x21C9B: bt       word ptr [rdi + 0xe], 0xd
0x21CA1: jae      0x21ce1
0x21CA3: mov      eax, ecx
0x21CA5: not      eax
0x21CA7: test     al, 4
0x21CA9: je       0x21ce1
0x21CAB: mov      eax, edx
0x21CAD: not      eax
0x21CAF: test     al, 4
0x21CB1: je       0x21ce1
0x21CB3: mov      eax, esi
0x21CB5: mov      dword ptr [rsp + 0x9c], eax
0x21CBC: cmp      eax, ecx
0x21CBE: jae      0x21d0f
0x21CC0: mov      ebx, eax
0x21CC2: add      eax, edx
0x21CC4: mov      rax, qword ptr [rax + r13]
0x21CC8: mov      qword ptr [r8 + rbx + 8], rax
0x21CCD: lea      rax, [rbx + 8]
0x21CD1: mov      dword ptr [rsp + 0x9c], eax
0x21CD8: mov      ecx, dword ptr [rsp + 0x98]
0x21CDF: jmp      0x21cbc
0x21CE1: mov      eax, esi
0x21CE3: mov      dword ptr [rsp + 0x9c], eax
0x21CEA: cmp      eax, ecx
0x21CEC: jae      0x21d0f
0x21CEE: mov      ebx, eax
0x21CF0: add      eax, edx
0x21CF2: mov      eax, dword ptr [rax + r13]
0x21CF6: mov      dword ptr [r8 + rbx + 8], eax
0x21CFB: lea      rax, [rbx + 4]
0x21CFF: mov      dword ptr [rsp + 0x9c], eax
0x21D06: mov      ecx, dword ptr [rsp + 0x98]
0x21D0D: jmp      0x21cea
0x21D0F: add      r8, r9
0x21D12: mov      qword ptr [rsp + 0x130], r8
0x21D1A: jmp      0x21c4d
0x21D1F: mov      r9d, 0x18
0x21D25: cmp      r8, r10
0x21D28: jae      0x21db7
0x21D2E: mov      eax, dword ptr [r8]
0x21D31: mov      dword ptr [rsp + 0xb0], eax
0x21D38: cmp      eax, dword ptr [rdi + 8]
0x21D3B: jae      0x21db7
0x21D3D: bt       word ptr [rdi + 0xe], 0xe
0x21D43: jae      0x21d49
0x21D45: test     al, 3
0x21D47: jne      0x21db7
0x21D49: mov      edx, dword ptr [r8 + 8]
0x21D4D: mov      dword ptr [rsp + 0x9c], edx
0x21D54: test     dword ptr [r8 + 4], edx
0x21D58: jne      0x21db7
0x21D5A: lea      rcx, [r13 + rax]
0x21D5F: mov      qword ptr [rsp + 0x138], rcx
0x21D67: mov      eax, dword ptr [rcx]
0x21D69: mov      dword ptr [rsp + 0x98], eax
0x21D70: mov      dword ptr [r8 + 0xc], eax
0x21D74: mov      eax, dword ptr [r8 + 4]
0x21D78: and      eax, dword ptr [rsp + 0x98]
0x21D7F: or       eax, edx
0x21D81: mov      dword ptr [rsp + 0x98], eax
0x21D88: mov      dword ptr [r8 + 0x10], eax
0x21D8C: test     byte ptr [rdi + 0xe], 2
0x21D90: je       0x21d9b
0x21D92: mov      eax, dword ptr [rsp + 0x98]
0x21D99: mov      dword ptr [rcx], eax
0x21D9B: test     byte ptr [rdi + 0xe], 4
0x21D9F: je       0x21da7
0x21DA1: mov      eax, dword ptr [rcx]
0x21DA3: mov      dword ptr [r8 + 0x10], eax
0x21DA7: add      r8, r9
0x21DAA: mov      qword ptr [rsp + 0x130], r8
0x21DB2: jmp      0x21d25
0x21DB7: cmp      r8, r10
0x21DBA: jae      0x21e64
0x21DC0: mov      dword ptr [rsp + 0x90], 0xc000000d
0x21DCB: bt       dword ptr [r12], 0x1f
0x21DD1: jae      0x21e75
0x21DD7: mov      rcx, r10
0x21DDA: sub      rcx, rdi
0x21DDD: sub      rcx, 0x30
0x21DE1: movabs   r9, 0x2aaaaaaaaaaaaaab
0x21DEB: mov      rax, r9
0x21DEE: imul     rcx
0x21DF1: mov      rbx, rdx
0x21DF4: sar      rbx, 2
0x21DF8: mov      rax, rbx
0x21DFB: shr      rax, 0x3f
0x21DFF: add      rbx, rax
0x21E02: mov      rcx, r8
0x21E05: sub      rcx, rdi
0x21E08: sub      rcx, 0x30
0x21E0C: mov      rax, r9
0x21E0F: imul     rcx
0x21E12: sar      rdx, 2
0x21E16: mov      rax, rdx
0x21E19: shr      rax, 0x3f
0x21E1D: add      rdx, rax
0x21E20: mov      eax, dword ptr [r8 + 4]
0x21E24: mov      dword ptr [rsp + 0x50], eax
0x21E28: mov      eax, dword ptr [r8]
0x21E2B: mov      dword ptr [rsp + 0x48], eax
0x21E2F: mov      eax, dword ptr [rdi + 8]
0x21E32: mov      dword ptr [rsp + 0x40], eax
0x21E36: mov      qword ptr [rsp + 0x38], rbx
0x21E3B: mov      qword ptr [rsp + 0x30], r10
0x21E40: mov      qword ptr [rsp + 0x28], rdx
0x21E45: mov      qword ptr [rsp + 0x20], r8
0x21E4A: mov      r9, r12
0x21E4D: lea      r8, [rip + 0x1b56c]  ; → L"佉呃彌䥓彖䅂归䕍位奒††摰⁸瀥†楢⁰瀥⠠甥 戠汩┠⁰┨⥵†楳⁺甥†景⁦甥†湣⁴甥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䍓䥓䵟义偉剏T쳌쳌쳌쳌쳌쳌佉呃彌䍓䥓䵟义偉剏⁔††景⁯瀥†景⁸瀥†摡⁯瀥†畢⁦瀥†灩⁬ⴥ甴†灯⁬ⴥ甴†敬⁮甥
쳌쳌쳌쳌쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓†景⁯瀥†"
0x21E54: mov      edx, 2
0x21E59: lea      ecx, [rdx + 0x4b]
0x21E5C: call     qword ptr [rip - 0xcc82]  ; → DbgPrintEx
0x21E62: jmp      0x21e75
0x21E64: sub      r8d, edi
0x21E67: mov      eax, r8d
0x21E6A: mov      qword ptr [r15 + 0x38], rax
0x21E6E: mov      dword ptr [rsp + 0x90], esi
0x21E75: jmp      0x21ea0
0x21E77: mov      dword ptr [rsp + 0x90], eax
0x21E7E: xor      esi, esi
0x21E80: mov      r12, qword ptr [rsp + 0xe0]
0x21E88: mov      r13, qword ptr [rsp + 0x100]
0x21E90: mov      rdi, qword ptr [rsp + 0x128]
0x21E98: mov      r15, qword ptr [rsp + 0xe8]
0x21EA0: mov      r8d, dword ptr [rdi + 8]
0x21EA4: mov      rdx, r13
0x21EA7: mov      rcx, r12
0x21EAA: call     0x29c2c
0x21EAF: jmp      0x28e31
0x21EB4: mov      dword ptr [rsp + 0x90], 0xc00000e6
0x21EBF: jmp      0x28e31
0x21EC4: cmp      ebx, 8  ← IOCTL 0x08 (RDMSR)
0x21EC7: jne      0x2215f
0x21ECD: lea      eax, [r13 - 0x400]
0x21ED4: cmp      eax, 0xfffc00
0x21ED9: ja       0x2215f
0x21EDF: mov      qword ptr [rsp + 0x100], rsi
0x21EE7: mov      qword ptr [rsp + 0xb8], rsi
0x21EEF: mov      rbx, qword ptr [rsp + 0x130]
0x21EF7: mov      rbx, qword ptr [rbx + 0x20]
0x21EFB: mov      qword ptr [rsp + 0x138], rbx
0x21F03: mov      r13, qword ptr [r15 + 0x70]
0x21F07: mov      qword ptr [rsp + 0x178], r13
0x21F0F: mov      edx, 8
0x21F14: lea      r8d, [rdx - 4]
0x21F18: mov      rcx, rbx
0x21F1B: call     qword ptr [rip - 0xcd01]  ; → ProbeForRead
0x21F21: mov      edx, dword ptr [rsp + 0x94]
0x21F28: mov      r8d, 8
0x21F2E: mov      rcx, r13
0x21F31: call     qword ptr [rip - 0xceb7]  ; → ProbeForWrite
0x21F37: mov      r14d, dword ptr [rbx]
0x21F3A: mov      dword ptr [rsp + 0xb8], r14d
0x21F42: mov      eax, dword ptr [rbx + 4]
0x21F45: mov      dword ptr [rsp + 0xa0], eax
0x21F4C: mov      dword ptr [rsp + 0xbc], eax
0x21F53: bt       dword ptr [r12], 0x14
0x21F59: jae      0x21f99
0x21F5B: mov      qword ptr [rsp + 0x48], rsi
0x21F60: mov      dword ptr [rsp + 0x40], r14d
0x21F65: mov      dword ptr [rsp + 0x38], eax
0x21F69: mov      eax, dword ptr [rsp + 0x94]
0x21F70: mov      dword ptr [rsp + 0x30], eax
0x21F74: mov      qword ptr [rsp + 0x28], r13
0x21F79: mov      dword ptr [rsp + 0x20], 8
0x21F81: mov      r9, rbx
0x21F84: lea      r8, [rip + 0x1b215]  ; → L"佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘洠灡┠⁰倠潲敢੤찀쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘洠灡┠⁰䴠灡数੤찀쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘"
0x21F8B: mov      edx, 2
0x21F90: lea      ecx, [rdx + 0x4b]
0x21F93: call     qword ptr [rip - 0xcdb9]  ; → DbgPrintEx
0x21F99: mov      r8d, dword ptr [rsp + 0x94]
0x21FA1: xor      r9d, r9d
0x21FA4: mov      rdx, qword ptr [rsp + 0xb8]
0x21FAC: mov      rcx, r12
0x21FAF: call     0x29a50
0x21FB4: mov      rdi, rax
0x21FB7: mov      qword ptr [rsp + 0x100], rax
0x21FBF: cmp      rax, rsi
0x21FC2: je       0x2209c
0x21FC8: bt       dword ptr [r12], 0x14
0x21FCE: jae      0x22015
0x21FD0: mov      qword ptr [rsp + 0x48], rax
0x21FD5: mov      dword ptr [rsp + 0x40], r14d
0x21FDA: mov      eax, dword ptr [rsp + 0xa0]
0x21FE1: mov      dword ptr [rsp + 0x38], eax
0x21FE5: mov      eax, dword ptr [rsp + 0x94]
0x21FEC: mov      dword ptr [rsp + 0x30], eax
0x21FF0: mov      qword ptr [rsp + 0x28], r13
0x21FF5: mov      dword ptr [rsp + 0x20], 8
0x21FFD: mov      r9, rbx
0x22000: lea      r8, [rip + 0x1b1f9]  ; → L"佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘洠灡┠⁰䴠灡数੤찀쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘洠灡┠⁰䰠慯敤੤찀쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘"
0x22007: mov      edx, 2
0x2200C: lea      ecx, [rdx + 0x4b]
0x2200F: call     qword ptr [rip - 0xce35]  ; → DbgPrintEx
0x22015: mov      r8d, dword ptr [rsp + 0x94]
0x2201D: mov      rdx, rdi
0x22020: mov      rcx, r13
0x22023: call     0x12e10
0x22028: bt       dword ptr [r12], 0x14
0x2202E: jae      0x22075
0x22030: mov      qword ptr [rsp + 0x48], rdi
0x22035: mov      dword ptr [rsp + 0x40], r14d
0x2203A: mov      eax, dword ptr [rsp + 0xa0]
0x22041: mov      dword ptr [rsp + 0x38], eax
0x22045: mov      eax, dword ptr [rsp + 0x94]
0x2204C: mov      dword ptr [rsp + 0x30], eax
0x22050: mov      qword ptr [rsp + 0x28], r13
0x22055: mov      dword ptr [rsp + 0x20], 8
0x2205D: mov      r9, rbx
0x22060: lea      r8, [rip + 0x1b1f9]  ; → L"佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘洠灡┠⁰䰠慯敤੤찀쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘洠灡┠⁰猠獴┠㠰╘ੳ찀쳌쳌쳌쳌쳌佉呃彌䥓彖䡐彙䕍位奒††景⁯瀥†慰⁤〥堸╟㠰⁘猠穩┠㘰⁘漠晦┠㐰"
0x22067: mov      edx, 2
0x2206C: lea      ecx, [rdx + 0x4b]
0x2206F: call     qword ptr [rip - 0xce95]  ; → DbgPrintEx
0x22075: mov      r8d, dword ptr [rsp + 0x94]
0x2207D: mov      rdx, rdi
0x22080: mov      rcx, r12
0x22083: call     0x29c2c
0x22088: mov      edx, dword ptr [rsp + 0x94]
0x2208F: mov      qword ptr [r15 + 0x38], rdx
0x22093: mov      dword ptr [rsp + 0x90], esi
0x2209A: jmp      0x220a7
0x2209C: mov      dword ptr [rsp + 0x90], 0xc00000e6
0x220A7: jmp      0x2215f
0x220AC: mov      ecx, eax
0x220AE: mov      dword ptr [rsp + 0x90], eax
0x220B5: mov      r12, qword ptr [rsp + 0xe0]
0x220BD: bt       dword ptr [r12], 0x1f
0x220C3: jae      0x22135
0x220C5: call     0x12acc
0x220CA: mov      qword ptr [rsp + 0x58], rax
0x220CF: mov      dword ptr [rsp + 0x50], ecx
0x220D3: mov      rbx, qword ptr [rsp + 0x100]
0x220DB: mov      qword ptr [rsp + 0x48], rbx
0x220E0: mov      eax, dword ptr [rsp + 0xb8]
0x220E7: mov      dword ptr [rsp + 0x40], eax
0x220EB: mov      eax, dword ptr [rsp + 0xbc]
0x220F2: mov      dword ptr [rsp + 0x38], eax
0x220F6: mov      eax, dword ptr [rsp + 0x94]
0x220FD: mov      dword ptr [rsp + 0x30], eax
0x22101: mov      rax, qword ptr [rsp + 0x178]
0x22109: mov      qword ptr [rsp + 0x28], rax
0x2210E: mov      dword ptr [rsp + 0x20], 8
0x22116: mov      r9, qword ptr [rsp + 0x138]
0x2211E: lea      r8, [rip + 0x1b19b]  ; → L"佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘洠灡┠⁰猠獴┠㠰╘ੳ찀쳌쳌쳌쳌쳌佉呃彌䥓彖䡐彙䕍位奒††景⁯瀥†慰⁤〥堸╟㠰⁘猠穩┠㘰⁘漠晦┠㐰⁘椠据┠㐰⁘氠湥┠㐰੘찀쳌쳌쳌쳌佉呃彌䥓彖䡐彙䕍位奒††景⁯瀥†慰⁤〥堸╟㠰⁘猠穩┠㘰੘찀쳌쳌쳌"
0x22125: mov      edx, 2
0x2212A: lea      ecx, [rdx + 0x4b]
0x2212D: call     qword ptr [rip - 0xcf53]  ; → DbgPrintEx
0x22133: jmp      0x2213d
0x22135: mov      rbx, qword ptr [rsp + 0x100]
0x2213D: xor      esi, esi
0x2213F: cmp      rbx, rsi
0x22142: je       0x22157
0x22144: mov      r8d, dword ptr [rsp + 0x94]
0x2214C: mov      rdx, rbx
0x2214F: mov      rcx, r12
0x22152: call     0x29c2c
0x22157: mov      r15, qword ptr [rsp + 0xe8]
0x2215F: jmp      0x28e31
0x22164: cmp      ebx, 8  ← IOCTL 0x08 (RDMSR)
0x22167: jb       0x224a3
0x2216D: lea      eax, [r13 - 4]
0x22171: cmp      eax, 0x3fffc
0x22176: ja       0x224a3
0x2217C: mov      r8, qword ptr [r15 + 0x18]
0x22180: mov      qword ptr [rsp + 0x130], r8
0x22188: mov      qword ptr [rsp + 0x100], rsi
0x22190: mov      rbx, qword ptr [r8]
0x22193: mov      qword ptr [rsp + 0xb8], rbx
0x2219B: cmp      dword ptr [rsp + 0xa0], 0x30
0x221A3: jne      0x2221e
0x221A5: mov      eax, dword ptr [r8 + 0x10]
0x221A9: mov      dword ptr [rsp + 0x9c], eax
0x221B0: cmp      eax, esi
0x221B2: je       0x2221e
0x221B4: mov      edx, eax
0x221B6: imul     edx, r13d
0x221BA: mov      dword ptr [rsp + 0x98], edx
0x221C1: bt       dword ptr [r12], 0x14
0x221C7: jae      0x22276
0x221CD: mov      rcx, rbx
0x221D0: shr      rcx, 0x20
0x221D4: mov      dword ptr [rsp + 0x48], r13d
0x221D9: mov      dword ptr [rsp + 0x40], eax
0x221DD: mov      eax, dword ptr [r8 + 0x14]
0x221E1: mov      dword ptr [rsp + 0x38], eax
0x221E5: mov      dword ptr [rsp + 0x30], edx
0x221E9: mov      eax, dword ptr [rsp + 0xb8]
0x221F0: mov      dword ptr [rsp + 0x28], eax
0x221F4: mov      dword ptr [rsp + 0x20], ecx
0x221F8: lea      r8, [rip + 0x1b121]  ; → L"佉呃彌䥓彖䡐彙䕍位奒††景⁯瀥†慰⁤〥堸╟㠰⁘猠穩┠㘰⁘漠晦┠㐰⁘椠据┠㐰⁘氠湥┠㐰੘찀쳌쳌쳌쳌佉呃彌䥓彖䡐彙䕍位奒††景⁯瀥†慰⁤〥堸╟㠰⁘猠穩┠㘰੘찀쳌쳌쳌佉呃彌䥓彖䅂归䕍位奒††摰⁸瀥†楢⁰瀥⠠甥 戠汩┠⁰┨⥵†楳⁺甥†景⁦甥†湣⁴甥
쳌쳌쳌쳌쳌쳌쳌"
0x221FF: mov      edx, 2
0x22204: mov      ecx, r11d
0x22207: call     qword ptr [rip - 0xd02d]  ; → DbgPrintEx
0x2220D: mov      r13d, dword ptr [rsp + 0x94]
0x22215: mov      edx, dword ptr [rsp + 0x98]
0x2221C: jmp      0x22276
0x2221E: mov      dword ptr [rsp + 0x9c], esi
0x22225: mov      edx, r13d
0x22228: mov      dword ptr [rsp + 0x98], edx
0x2222F: bt       dword ptr [r12], 0x14
0x22235: jae      0x22276
0x22237: mov      dword ptr [rsp + 0x30], r13d
0x2223C: mov      eax, dword ptr [rsp + 0xb8]
0x22243: mov      dword ptr [rsp + 0x28], eax
0x22247: mov      eax, dword ptr [rsp + 0xbc]
0x2224E: mov      dword ptr [rsp + 0x20], eax
0x22252: lea      r8, [rip + 0x1b127]  ; → L"佉呃彌䥓彖䡐彙䕍位奒††景⁯瀥†慰⁤〥堸╟㠰⁘猠穩┠㘰੘찀쳌쳌쳌佉呃彌䥓彖䅂归䕍位奒††摰⁸瀥†楢⁰瀥⠠甥 戠汩┠⁰┨⥵†楳⁺甥†景⁦甥†湣⁴甥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䍓䥓䵟义偉剏T쳌쳌쳌쳌쳌쳌佉呃彌䍓䥓䵟义偉剏⁔††景⁯瀥†景⁸瀥†摡⁯瀥†畢⁦瀥†灩⁬ⴥ甴"
0x22259: mov      edx, 2
0x2225E: mov      ecx, r11d
0x22261: call     qword ptr [rip - 0xd087]  ; → DbgPrintEx
0x22267: mov      r13d, dword ptr [rsp + 0x94]
0x2226F: mov      edx, dword ptr [rsp + 0x98]
0x22276: mov      r9d, esi
0x22279: cmp      r13d, 0x200
0x22280: setbe    r9b
0x22284: mov      r8d, edx
0x22287: mov      rdx, rbx
0x2228A: mov      rcx, r12
0x2228D: call     0x29a50
0x22292: mov      rdx, rax
0x22295: mov      qword ptr [rsp + 0x100], rax
0x2229D: cmp      rax, rsi
0x222A0: je       0x22456
0x222A6: mov      eax, dword ptr [rsp + 0x9c]
0x222AD: cmp      eax, esi
0x222AF: jne      0x222fd
0x222B1: mov      qword ptr [rsp + 0x2b8], r14
0x222B9: mov      ebx, dword ptr [rsp + 0x94]
0x222C0: add      rbx, r14
0x222C3: mov      rcx, rdx
0x222C6: mov      qword ptr [rsp + 0x2c8], rdx
0x222CE: cmp      rdi, rbx
0x222D1: jae      0x22432
0x222D7: mov      eax, dword ptr [rcx]
0x222D9: mov      dword ptr [rdi], eax
0x222DB: add      rdi, 4
0x222DF: mov      qword ptr [rsp + 0x2b8], rdi
0x222E7: add      rcx, 4
0x222EB: mov      qword ptr [rsp + 0x2c8], rcx
0x222F3: mov      rdx, qword ptr [rsp + 0x100]
0x222FB: jmp      0x222ce
0x222FD: mov      rcx, qword ptr [rsp + 0x130]
0x22305: cmp      dword ptr [rcx + 0x1c], 4
0x22309: jne      0x22360
0x2230B: mov      ecx, dword ptr [rcx + 0x14]
0x2230E: add      rcx, rdx
0x22311: mov      qword ptr [rsp + 0x288], rcx
0x22319: mov      qword ptr [rsp + 0x280], r14
0x22321: mov      ebx, dword ptr [rsp + 0x94]
0x22328: add      rbx, r14
0x2232B: cmp      rdi, rbx
0x2232E: jae      0x22432
0x22334: mov      eax, dword ptr [rcx]
0x22336: mov      dword ptr [rdi], eax
0x22338: add      rdi, 4
0x2233C: mov      qword ptr [rsp + 0x280], rdi
0x22344: mov      eax, dword ptr [rsp + 0x9c]
0x2234B: add      rcx, rax
0x2234E: mov      qword ptr [rsp + 0x288], rcx
0x22356: mov      rdx, qword ptr [rsp + 0x100]
0x2235E: jmp      0x2232b
0x22360: mov      rdi, qword ptr [rcx + 8]
0x22364: mov      qword ptr [rsp + 0x2b0], rdi
0x2236C: mov      r8d, dword ptr [rcx + 0x18]
0x22370: mov      dword ptr [rsp + 0xa0], r8d
0x22378: mov      ebx, dword ptr [rcx + 0x14]
0x2237B: add      rbx, rdx
0x2237E: mov      qword ptr [rsp + 0x290], rbx
0x22386: mov      qword ptr [rsp + 0x2c0], r14
0x2238E: mov      r13d, dword ptr [rsp + 0x94]
0x22396: add      r13, r14
0x22399: cmp      r14, r13
0x2239C: jae      0x22432
0x223A2: test     dil, 1
0x223A6: jne      0x223b4
0x223A8: mov      cl, sil
0x223AB: mov      byte ptr [rsp + 0xf0], cl
0x223B2: jmp      0x22401
0x223B4: mov      cl, byte ptr [rbx]
0x223B6: mov      byte ptr [rsp + 0xf0], cl
0x223BD: cmp      cl, sil
0x223C0: jne      0x223f2
0x223C2: cmp      r8d, esi
0x223C5: je       0x223f2
0x223C7: mov      ecx, r8d
0x223CA: call     qword ptr [rip - 0xd3b8]  ; → KeStallExecutionProcessor
0x223D0: mov      cl, byte ptr [rbx]
0x223D2: mov      byte ptr [rsp + 0xf0], cl
0x223D9: mov      eax, dword ptr [rsp + 0x9c]
0x223E0: mov      rdx, qword ptr [rsp + 0x100]
0x223E8: mov      r8d, dword ptr [rsp + 0xa0]
0x223F0: jmp      0x22401
0x223F2: mov      eax, dword ptr [rsp + 0x9c]
0x223F9: mov      rdx, qword ptr [rsp + 0x100]
0x22401: mov      byte ptr [r14], cl
0x22404: add      r14, 1
0x22408: mov      qword ptr [rsp + 0x2c0], r14
0x22410: add      rbx, rax
0x22413: mov      qword ptr [rsp + 0x290], rbx
0x2241B: shr      rdi, 1
0x2241E: mov      qword ptr [rsp + 0x2b0], rdi
0x22426: mov      eax, dword ptr [rsp + 0x9c]
0x2242D: jmp      0x22399
0x22432: mov      r8d, dword ptr [rsp + 0x98]
0x2243A: mov      rcx, r12
0x2243D: call     0x29c2c
0x22442: mov      edx, dword ptr [rsp + 0x94]
0x22449: mov      qword ptr [r15 + 0x38], rdx
0x2244D: mov      dword ptr [rsp + 0x90], esi
0x22454: jmp      0x22461
0x22456: mov      dword ptr [rsp + 0x90], 0xc00000e6
0x22461: jmp      0x224a3
0x22463: mov      dword ptr [rsp + 0x90], eax
0x2246A: mov      rdx, qword ptr [rsp + 0x100]
0x22472: xor      esi, esi
0x22474: cmp      rdx, rsi
0x22477: je       0x22493
0x22479: mov      r8d, dword ptr [rsp + 0x98]
0x22481: mov      r12, qword ptr [rsp + 0xe0]
0x22489: mov      rcx, r12
0x2248C: call     0x29c2c
0x22491: jmp      0x2249b
0x22493: mov      r12, qword ptr [rsp + 0xe0]
0x2249B: mov      r15, qword ptr [rsp + 0xe8]
0x224A3: jmp      0x28e31
0x224A8: cmp      ebx, 0xc  ← IOCTL 0x0C (WRMSR)
0x224AB: jb       0x225ed
0x224B1: cmp      r13d, 0xc  ← IOCTL 0x0C (WRMSR)
0x224B5: jb       0x225ed
0x224BB: mov      ebx, dword ptr [r14]
0x224BE: mov      dword ptr [rsp + 0xb0], ebx
0x224C5: mov      eax, dword ptr [r14 + 4]
0x224C9: mov      dword ptr [rsp + 0xd0], eax
0x224D0: mov      ecx, dword ptr [r14 + 8]
0x224D4: mov      dword ptr [rsp + 0xd4], ecx
0x224DB: cmp      ebx, 0x38d
0x224E1: je       0x2251b
0x224E3: cmp      ebx, 0x38f
0x224E9: je       0x2251b
0x224EB: cmp      ebx, 0x19c
0x224F1: je       0x2251b
0x224F3: cmp      ebx, 0x110a
0x224F9: je       0x2251b
0x224FB: cmp      ebx, 0x1147
0x22501: je       0x2251b
0x22503: cmp      ebx, 0xc0000086
0x22509: je       0x2251b
0x2250B: mov      dword ptr [rsp + 0x90], 0xc0000022
0x22516: jmp      0x225ed
0x2251B: cmp      ebx, esi
0x2251D: jne      0x2252f
0x2251F: mov      dword ptr [rsp + 0x90], 0xc000001d
0x2252A: jmp      0x225ed
0x2252F: test     byte ptr [r12], 0x20
0x22534: je       0x22557
0x22536: mov      dword ptr [rsp + 0x30], eax
0x2253A: mov      dword ptr [rsp + 0x28], ecx
0x2253E: mov      dword ptr [rsp + 0x20], ebx
0x22542: lea      r8, [rip + 0x1a7e7]  ; → L"佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰⁘猠獴┠㠰╘ੳ찀쳌쳌쳌쳌쳌佉呃彌䥓彖䕇彔偃录剃‰†景⁯瀥
佉呃彌䥓彖䍐䉉单††††獤⁴瀥†慰⁤〥堸╟㠰⁘洠灡┠⁰猠捲┠⁰氠湥┠㐰⁘漠晦┠㐰"
0x22549: mov      edx, 2
0x2254E: mov      ecx, r11d
0x22551: call     qword ptr [rip - 0xd377]  ; → DbgPrintEx
0x22557: mov      rdx, qword ptr [rsp + 0xd0]
0x2255F: shr      rdx, 0x20
0x22563: mov      ecx, ebx
0x22565: mov      eax, dword ptr [rsp + 0xd0]
0x2256C: wrmsr    
0x2256E: mov      qword ptr [r15 + 0x38], 0xc
0x22576: mov      dword ptr [rsp + 0x90], esi
0x2257D: jmp      0x225ed
0x2257F: mov      ecx, eax
0x22581: mov      dword ptr [rsp + 0x90], eax
0x22588: mov      r12, qword ptr [rsp + 0xe0]
0x22590: test     byte ptr [r12], 0x20
0x22595: je       0x225e3
0x22597: call     0x12acc
0x2259C: mov      qword ptr [rsp + 0x40], rax
0x225A1: mov      dword ptr [rsp + 0x38], ecx
0x225A5: mov      eax, dword ptr [rsp + 0xd0]
0x225AC: mov      dword ptr [rsp + 0x30], eax
0x225B0: mov      eax, dword ptr [rsp + 0xd4]
0x225B7: mov      dword ptr [rsp + 0x28], eax
0x225BB: mov      eax, dword ptr [rsp + 0xb0]
0x225C2: mov      dword ptr [rsp + 0x20], eax
0x225C6: mov      r9, qword ptr [rsp + 0xb8]
0x225CE: lea      r8, [rip + 0x1a79b]  ; → L"佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰⁘猠獴┠㠰╘ੳ찀쳌쳌쳌쳌쳌佉呃彌䥓彖䕇彔偃录剃‰†景⁯瀥
佉呃彌䥓彖䍐䉉单††††獤⁴瀥†慰⁤〥堸╟㠰⁘洠灡┠⁰猠捲┠⁰氠湥┠㐰⁘漠晦┠㐰੘찀쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䵁彄䍐敉†††灶⁷甥㸠眠扤┠Ⱶ戠摡椠汰"
0x225D5: mov      edx, 2
0x225DA: lea      ecx, [rdx + 0x4b]
0x225DD: call     qword ptr [rip - 0xd403]  ; → DbgPrintEx
0x225E3: xor      esi, esi
0x225E5: mov      r15, qword ptr [rsp + 0xe8]
0x225ED: jmp      0x28e31
0x225F2: cmp      ebx, 4
0x225F5: jb       0x2271e
0x225FB: cmp      r13d, 8  ← IOCTL 0x08 (RDMSR)
0x225FF: jb       0x2271e
0x22605: mov      r8d, dword ptr [r14]
0x22608: mov      dword ptr [rsp + 0xb0], r8d
0x22610: cmp      r8d, 0xc0010117
0x22617: jne      0x22629
0x22619: mov      dword ptr [rsp + 0x90], 0xc000001d
0x22624: jmp      0x2271e
0x22629: cmp      r8d, esi
0x2262C: jne      0x2263e
0x2262E: mov      dword ptr [rsp + 0x90], 0xc000001d
0x22639: jmp      0x2271e
0x2263E: cmp      r8d, 0x8b
0x22645: jne      0x2266a
0x22647: mov      eax, 1
0x2264C: cpuid    
0x2264E: mov      dword ptr [rsp + 0x2a0], eax
0x22655: mov      dword ptr [rsp + 0x2a4], ebx
0x2265C: mov      dword ptr [rsp + 0x2a8], ecx
0x22663: mov      dword ptr [rsp + 0x2ac], edx
0x2266A: mov      ecx, r8d
0x2266D: rdmsr    
0x2266F: shl      rdx, 0x20
0x22673: or       rax, rdx
0x22676: mov      qword ptr [rsp + 0xd0], rax
0x2267E: mov      qword ptr [r14], rax
0x22681: test     byte ptr [r12], 0x20
0x22686: je       0x226b5
0x22688: shr      rax, 0x20
0x2268C: mov      ecx, dword ptr [rsp + 0xd0]
0x22693: mov      dword ptr [rsp + 0x30], ecx
0x22697: mov      dword ptr [rsp + 0x28], eax
0x2269B: mov      dword ptr [rsp + 0x20], r8d
0x226A0: lea      r8, [rip + 0x1a609]  ; → L"佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†瑳⁳〥堸猥
쳌쳌쳌쳌쳌佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰⁘猠獴┠㠰"
0x226A7: mov      edx, 2
0x226AC: mov      ecx, r11d
0x226AF: call     qword ptr [rip - 0xd4d5]  ; → DbgPrintEx
0x226B5: mov      qword ptr [r15 + 0x38], 8
0x226BD: mov      dword ptr [rsp + 0x90], esi
0x226C4: jmp      0x2271e
0x226C6: mov      ecx, eax
0x226C8: mov      dword ptr [rsp + 0x90], eax
0x226CF: mov      r12, qword ptr [rsp + 0xe0]
0x226D7: test     byte ptr [r12], 0x20
0x226DC: je       0x22714
0x226DE: call     0x12acc
0x226E3: mov      qword ptr [rsp + 0x30], rax
0x226E8: mov      dword ptr [rsp + 0x28], ecx
0x226EC: mov      eax, dword ptr [rsp + 0xb0]
0x226F3: mov      dword ptr [rsp + 0x20], eax
0x226F7: mov      r9, qword ptr [rsp + 0xb8]
0x226FF: lea      r8, [rip + 0x1a5ea]  ; → L"佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†瑳⁳〥堸猥
쳌쳌쳌쳌쳌佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰⁘猠獴┠㠰╘ੳ찀쳌쳌쳌쳌쳌佉呃彌䥓彖䕇彔偃录剃‰†景⁯瀥
佉呃彌䥓彖䍐䉉单"
0x22706: mov      edx, 2
0x2270B: lea      ecx, [rdx + 0x4b]
0x2270E: call     qword ptr [rip - 0xd534]  ; → DbgPrintEx
0x22714: xor      esi, esi
0x22716: mov      r15, qword ptr [rsp + 0xe8]
0x2271E: jmp      0x28e31
0x22723: cmp      r9, 0x66666666
0x2272A: je       0x2273c
0x2272C: mov      dword ptr [rsp + 0x90], 0xc0000010
0x22737: jmp      0x28e31
0x2273C: mov      r14, qword ptr [r15 + 0x70]
0x22740: mov      qword ptr [rsp + 0x148], r14
0x22748: mov      rcx, r14
0x2274B: mov      qword ptr [rsp + 0x230], rcx
0x22753: cmp      r13d, esi
0x22756: jne      0x22774
0x22758: cmp      ebx, 0xc  ← IOCTL 0x0C (WRMSR)
0x2275B: jne      0x22774
0x2275D: mov      rdx, rdi
0x22760: mov      rcx, r12
0x22763: call     0x37c60
0x22768: mov      dword ptr [rsp + 0x90], eax
0x2276F: jmp      0x28e31
0x22774: mov      eax, 0x40
0x22779: cmp      r13d, eax
0x2277C: jb       0x227d9
0x2277E: lea      rdx, [rip + 0x1a4db]  ; → L"㕖㠮‵䈠極瑬䨠湡ㄠ‴〲㘲愠⁴㠰ㄺ㨶㠴†䑗⁋〶㄰ㄮ〸〰†V쳌쳌쳌쳌㕖㠮5쳌쳌쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†瑳⁳〥堸猥
쳌쳌쳌쳌쳌佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥"
0x22785: mov      byte ptr [r14], 0x56
0x22789: add      rdx, 1
0x2278D: add      r14, 1
0x22791: mov      al, byte ptr [rdx]
0x22793: mov      byte ptr [r14], al
0x22796: cmp      al, sil
0x22799: jne      0x22789
0x2279B: mov      byte ptr [r14], 0x31
0x2279F: mov      byte ptr [r14 + 1], 0x34
0x227A4: mov      byte ptr [r14 + 2], 0x2e
0x227A9: mov      byte ptr [r14 + 3], 0x30
0x227AE: mov      byte ptr [r14 + 4], 0x30
0x227B3: mov      byte ptr [r14 + 5], sil
0x227B7: add      r14, 6
0x227BB: mov      qword ptr [rsp + 0x148], r14
0x227C3: sub      r14d, ecx
0x227C6: mov      eax, r14d
0x227C9: mov      qword ptr [r15 + 0x38], rax
0x227CD: mov      dword ptr [rsp + 0x90], esi
0x227D4: jmp      0x28e31
0x227D9: cmp      r13d, 6
0x227DD: jb       0x28e31
0x227E3: mov      eax, dword ptr [rip + 0x1a4b7]  ; → L"㕖㠮5쳌쳌쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†瑳⁳〥堸猥
쳌쳌쳌쳌쳌佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥"
0x227E9: mov      dword ptr [rcx], eax
0x227EB: movzx    eax, word ptr [rip + 0x1a4b2]  ; → L"5쳌쳌쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†瑳⁳〥堸猥
쳌쳌쳌쳌쳌佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖剗卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟"
0x227F2: mov      word ptr [rcx + 4], ax
0x227F6: mov      qword ptr [r15 + 0x38], 6
0x227FE: mov      dword ptr [rsp + 0x90], esi
0x22805: jmp      0x28e31
0x2280A: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x22815: jmp      0x28e31
0x2281A: cmp      edx, 0x1c
0x2281D: je       0x22bea
0x22823: cmp      edx, 0x20
0x22826: je       0x22b77
0x2282C: cmp      edx, 0x24
0x2282F: je       0x2293e
0x22835: cmp      edx, 0x28
0x22838: je       0x2290d
0x2283E: cmp      edx, 0x2c
0x22841: je       0x22874
0x22843: cmp      edx, 0x30
0x22846: jne      0x28372
0x2284C: cmp      r13d, 0x64
0x22850: jb       0x28e31
0x22856: mov      rdx, r14
0x22859: mov      rcx, r12
0x2285C: call     0x301fc
0x22861: movsxd   rcx, eax
0x22864: mov      qword ptr [r15 + 0x38], rcx
0x22868: mov      dword ptr [rsp + 0x90], esi
0x2286F: jmp      0x28e31
0x22874: or       cx, 0xffff
0x22879: call     qword ptr [r12 + 0x120]
0x22881: mov      edi, eax
0x22883: mov      dword ptr [rsp + 0x9c], eax
0x2288A: mov      rcx, r15
0x2288D: call     qword ptr [rip - 0xd7e3]  ; → IoIs32bitProcess
0x22893: cmp      al, sil
0x22896: je       0x228bc
0x22898: call     qword ptr [r12 + 0x118]
0x228A0: movzx    r11d, ax
0x228A4: shl      r11d, 5
0x228A8: je       0x228bc
0x228AA: cmp      edi, r11d
0x228AD: cmovb    r11d, edi
0x228B1: mov      edi, r11d
0x228B4: mov      dword ptr [rsp + 0x9c], r11d
0x228BC: lea      eax, [rdi + rdi*8]
0x228BF: lea      r8d, [rax*8 + 0x40]
0x228C7: mov      dword ptr [rsp + 0x98], r8d
0x228CF: mov      eax, 0x40
0x228D4: cmp      ebx, eax
0x228D6: jb       0x28e31
0x228DC: cmp      dword ptr [rsp + 0x94], r8d
0x228E4: jb       0x28e31
0x228EA: lea      rax, [r15 + 0x30]
0x228EE: mov      qword ptr [rsp + 0x20], rax
0x228F3: mov      r9d, edi
0x228F6: mov      rdx, r14
0x228F9: mov      rcx, r12
0x228FC: call     0x12164
0x22901: mov      dword ptr [rsp + 0x90], eax
0x22908: jmp      0x28e31
0x2290D: mov      eax, 0x80
0x22912: cmp      ebx, eax
0x22914: jb       0x28e31
0x2291A: cmp      r13d, eax
0x2291D: jb       0x28e31
0x22923: lea      r8, [r15 + 0x30]
0x22927: mov      rdx, r14
0x2292A: mov      rcx, r12
0x2292D: call     0x11d98
0x22932: mov      dword ptr [rsp + 0x90], eax
0x22939: jmp      0x28e31
0x2293E: cmp      ebx, 4
0x22941: jb       0x22953
0x22943: mov      ecx, dword ptr [r14]
0x22946: bts      ecx, 0x1f
0x2294A: mov      dword ptr [rsp + 0xb0], ecx
0x22951: jmp      0x2295f
0x22953: mov      ecx, 0x80000010
0x22958: mov      dword ptr [rsp + 0xb0], ecx
0x2295F: cmp      r13d, eax
0x22962: jb       0x28e31
0x22968: mov      rcx, qword ptr [r15 + 0x18]
0x2296C: mov      qword ptr [rsp + 0x128], rcx
0x22974: mov      qword ptr [rsp + 0x120], rcx
0x2297C: lea      r14, [rcx + 8]
0x22980: mov      qword ptr [rsp + 0x130], r14
0x22988: mov      eax, r13d
0x2298B: sub      rax, 8
0x2298F: shr      rax, 4
0x22993: shl      eax, 8
0x22996: mov      dword ptr [rsp + 0x94], eax
0x2299D: call     qword ptr [r12 + 0x110]
0x229A5: mov      rdi, rax
0x229A8: mov      dword ptr [rsp + 0xa0], edi
0x229AF: mov      eax, esi
0x229B1: mov      dword ptr [rsp + 0xd8], eax
0x229B8: mov      rbx, qword ptr [rsp + 0xd0]
0x229C0: mov      r13d, 0x10
0x229C6: cmp      eax, dword ptr [rsp + 0x94]
0x229CD: jae      0x22b5c
0x229D3: mov      eax, esi
0x229D5: mov      dword ptr [rsp + 0x98], eax
0x229DC: cmp      eax, 0x64
0x229DF: jae      0x22a24
0x229E1: mov      ecx, 0x150
0x229E6: rdmsr    
0x229E8: shl      rdx, 0x20
0x229EC: or       rax, rdx
0x229EF: mov      rbx, rax
0x229F2: mov      qword ptr [rsp + 0xd0], rax
0x229FA: shr      rax, 0x20
0x229FE: not      eax
0x22A00: bt       eax, 0x1f
0x22A04: jb       0x22a24
0x22A06: mov      ecx, 2
0x22A0B: call     qword ptr [rip - 0xd9f9]  ; → KeStallExecutionProcessor
0x22A11: mov      eax, dword ptr [rsp + 0x98]
0x22A18: add      eax, 1
0x22A1B: mov      dword ptr [rsp + 0x98], eax
0x22A22: jmp      0x229dc
0x22A24: bt       dword ptr [rsp + 0xd4], 0x1f
0x22A2D: jae      0x22a3f
0x22A2F: mov      dword ptr [r14 + 0xc], 0x102
0x22A37: mov      qword ptr [r14], rbx
0x22A3A: jmp      0x22acd
0x22A3F: mov      ecx, dword ptr [rsp + 0xd8]
0x22A46: mov      eax, dword ptr [rsp + 0xb0]
0x22A4D: add      eax, ecx
0x22A4F: mov      dword ptr [rsp + 0xd4], eax
0x22A56: mov      dword ptr [rsp + 0xd0], esi
0x22A5D: mov      rbx, qword ptr [rsp + 0xd0]
0x22A65: mov      rdx, rbx
0x22A68: shr      rdx, 0x20
0x22A6C: mov      ecx, 0x150
0x22A71: mov      eax, ebx
0x22A73: wrmsr    
0x22A75: mov      eax, esi
0x22A77: mov      dword ptr [rsp + 0x98], eax
0x22A7E: cmp      eax, 0x64
0x22A81: jae      0x22ac6
0x22A83: mov      ecx, 0x150
0x22A88: rdmsr    
0x22A8A: shl      rdx, 0x20
0x22A8E: or       rax, rdx
0x22A91: mov      rbx, rax
0x22A94: mov      qword ptr [rsp + 0xd0], rax
0x22A9C: shr      rax, 0x20
0x22AA0: not      eax
0x22AA2: bt       eax, 0x1f
0x22AA6: jb       0x22ac6
0x22AA8: mov      ecx, 2
0x22AAD: call     qword ptr [rip - 0xda9b]  ; → KeStallExecutionProcessor
0x22AB3: mov      eax, dword ptr [rsp + 0x98]
0x22ABA: add      eax, 1
0x22ABD: mov      dword ptr [rsp + 0x98], eax
0x22AC4: jmp      0x22a7e
0x22AC6: mov      dword ptr [r14 + 0xc], esi
0x22ACA: mov      qword ptr [r14], rbx
0x22ACD: jmp      0x22b1e
0x22ACF: mov      r14, qword ptr [rsp + 0x130]
0x22AD7: mov      ecx, dword ptr [rsp + 0xd8]
0x22ADE: mov      dword ptr [r14 + 4], ecx
0x22AE2: xor      esi, esi
0x22AE4: mov      dword ptr [r14], esi
0x22AE7: mov      dword ptr [r14 + 0xc], eax
0x22AEB: lea      r13d, [rsi + 0x10]
0x22AEF: mov      r12, qword ptr [rsp + 0xe0]
0x22AF7: mov      rbx, qword ptr [rsp + 0xd0]
0x22AFF: mov      rax, qword ptr [rsp + 0x120]
0x22B07: mov      qword ptr [rsp + 0x128], rax
0x22B0F: mov      edi, dword ptr [rsp + 0xa0]
0x22B16: mov      r15, qword ptr [rsp + 0xe8]
0x22B1E: xor      ecx, ecx
0x22B20: call     qword ptr [r12 + 0x110]
0x22B28: mov      ecx, eax
0x22B2A: sub      ecx, edi
0x22B2C: mov      dword ptr [r14 + 8], ecx
0x22B30: mov      edi, eax
0x22B32: mov      dword ptr [rsp + 0xa0], eax
0x22B39: mov      eax, dword ptr [rsp + 0xd8]
0x22B40: add      eax, 0x100
0x22B45: mov      dword ptr [rsp + 0xd8], eax
0x22B4C: add      r14, r13
0x22B4F: mov      qword ptr [rsp + 0x130], r14
0x22B57: jmp      0x229c6
0x22B5C: sub      r14d, dword ptr [rsp + 0x128]
0x22B64: mov      eax, r14d
0x22B67: mov      qword ptr [r15 + 0x38], rax
0x22B6B: mov      dword ptr [rsp + 0x90], esi
0x22B72: jmp      0x28e31
0x22B77: cmp      ebx, 4
0x22B7A: jb       0x28e31
0x22B80: cmp      r13d, 4
0x22B84: jb       0x28e31
0x22B8A: and      dword ptr [r14], 0xffff00
0x22B91: bts      dword ptr [r14], 0x1c
0x22B96: mov      dword ptr [rsp + 0x28], 4
0x22B9E: mov      dword ptr [rsp + 0x20], 0xd0
0x22BA6: mov      r9, r14
0x22BA9: xor      r8d, r8d
0x22BAC: xor      edx, edx
0x22BAE: mov      rcx, r12
0x22BB1: call     0x11ae4
0x22BB6: mov      dword ptr [rsp + 0x28], 4
0x22BBE: mov      dword ptr [rsp + 0x20], 0xd4
0x22BC6: mov      r9, r14
0x22BC9: xor      r8d, r8d
0x22BCC: xor      edx, edx
0x22BCE: mov      rcx, r12
0x22BD1: call     0x119c8
0x22BD6: mov      qword ptr [r15 + 0x38], 4
0x22BDE: mov      dword ptr [rsp + 0x90], esi
0x22BE5: jmp      0x28e31
0x22BEA: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x22BF5: jmp      0x28e31
0x22BFA: mov      eax, 0x40
0x22BFF: or       dword ptr [r12 + 8], eax
0x22C04: mov      eax, esi
0x22C06: cmp      dword ptr [r12 + 0x30], esi
0x22C0B: setne    al
0x22C0E: mov      dword ptr [r12 + 0x30], eax
0x22C13: mov      eax, esi
0x22C15: cmp      dword ptr [r12 + 0x38], esi
0x22C1A: setne    al
0x22C1D: mov      dword ptr [r12 + 0x38], eax
0x22C22: mov      qword ptr [r15 + 0x38], rsi
0x22C26: mov      dword ptr [rsp + 0x90], esi
0x22C2D: jmp      0x28e31
0x22C32: cmp      edx, 0x54
0x22C35: ja       0x235ca
0x22C3B: cmp      edx, 0x54
0x22C3E: je       0x23580
0x22C44: cmp      edx, 0x3c
0x22C47: je       0x23537
0x22C4D: mov      eax, 0x40
0x22C52: cmp      edx, eax
0x22C54: je       0x23251
0x22C5A: cmp      edx, 0x44  ← IOCTL 0x44 (Port_IO)
0x22C5D: je       0x22f60
0x22C63: cmp      edx, 0x48  ← IOCTL 0x48 (PCI_Read)
0x22C66: je       0x22ee4
0x22C6C: cmp      edx, 0x4c
0x22C6F: je       0x22d2e
0x22C75: cmp      edx, 0x50
0x22C78: jne      0x28372
0x22C7E: cmp      ebx, 4
0x22C81: jb       0x28e31
0x22C87: cmp      r13d, 8  ← IOCTL 0x08 (RDMSR)
0x22C8B: jb       0x28e31
0x22C91: mov      ebx, dword ptr [r14]
0x22C94: mov      dword ptr [rsp + 0x9c], ebx
0x22C9B: mov      ecx, 0x1000
0x22CA0: mov      dword ptr [rsp + 0x98], ecx
0x22CA7: cmp      ebx, ecx
0x22CA9: jae      0x22cd1
0x22CAB: movzx    edx, bx
0x22CAE: in       al, dx
0x22CAF: cmp      al, 0xff
0x22CB1: jne      0x22cca
0x22CB3: add      ebx, 1
0x22CB6: mov      dword ptr [rsp + 0x9c], ebx
0x22CBD: mov      ecx, dword ptr [rsp + 0x98]
0x22CC4: cmp      ebx, ecx
0x22CC6: jb       0x22cab
0x22CC8: jmp      0x22cd1
0x22CCA: mov      ecx, dword ptr [rsp + 0x98]
0x22CD1: cmp      ebx, ecx
0x22CD3: jb       0x22ce5
0x22CD5: mov      dword ptr [rsp + 0x90], 0xc0000225
0x22CE0: jmp      0x28e31
0x22CE5: mov      dword ptr [r14], ebx
0x22CE8: add      ebx, 1
0x22CEB: mov      dword ptr [rsp + 0x9c], ebx
0x22CF2: cmp      ebx, dword ptr [rsp + 0x98]
0x22CF9: jae      0x22d16
0x22CFB: movzx    edx, bx
0x22CFE: in       al, dx
0x22CFF: cmp      al, 0xff
0x22D01: je       0x22d0f
0x22D03: add      ebx, 1
0x22D06: cmp      ebx, dword ptr [rsp + 0x98]
0x22D0D: jb       0x22cfb
0x22D0F: mov      dword ptr [rsp + 0x9c], ebx
0x22D16: mov      dword ptr [r14 + 4], ebx
0x22D1A: mov      qword ptr [r15 + 0x38], 8
0x22D22: mov      dword ptr [rsp + 0x90], esi
0x22D29: jmp      0x28e31
0x22D2E: cmp      ebx, 0xc  ← IOCTL 0x0C (WRMSR)
0x22D31: jb       0x28e31
0x22D37: cmp      r13d, eax
0x22D3A: jb       0x28e31
0x22D40: test     r13b, 3
0x22D44: jne      0x28e31
0x22D4A: mov      eax, dword ptr [r14]
0x22D4D: mov      dword ptr [rsp + 0xd8], eax
0x22D54: mov      r13d, dword ptr [r14 + 4]
0x22D58: mov      ecx, dword ptr [r14 + 8]
0x22D5C: mov      dword ptr [rsp + 0xa0], ecx
0x22D63: movzx    r14d, al
0x22D67: mov      dword ptr [rsp + 0x28], 4
0x22D6F: mov      dword ptr [rsp + 0x20], ecx
0x22D73: lea      r9, [rsp + 0x98]
0x22D7B: mov      r8d, r13d
0x22D7E: mov      edx, r14d
0x22D81: mov      rcx, r12
0x22D84: call     0x119c8
0x22D89: cmp      eax, 4
0x22D8C: jne      0x22ed4
0x22D92: cmp      byte ptr [rsp + 0x98], 3
0x22D9A: jne      0x22ed4
0x22DA0: mov      ebx, esi
0x22DA2: mov      dword ptr [rsp + 0x9c], ebx
0x22DA9: cmp      dword ptr [rsp + 0x94], esi
0x22DB0: jbe      0x22ec2
0x22DB6: mov      ecx, dword ptr [rsp + 0xa0]
0x22DBD: add      ecx, 2
0x22DC0: mov      dword ptr [rsp + 0xd0], ecx
0x22DC7: movzx    eax, bx
0x22DCA: and      ax, 0xfffc
0x22DCE: mov      word ptr [rsp + 0xc8], ax
0x22DD6: mov      dword ptr [rsp + 0x28], 2
0x22DDE: mov      dword ptr [rsp + 0x20], ecx
0x22DE2: lea      r9, [rsp + 0xc8]
0x22DEA: mov      r8d, r13d
0x22DED: mov      edx, r14d
0x22DF0: mov      rcx, r12
0x22DF3: call     0x11ae4
0x22DF8: cmp      eax, 2
0x22DFB: jne      0x22ec2
0x22E01: mov      dword ptr [rsp + 0x98], esi
0x22E08: mov      dword ptr [rsp + 0x28], 2
0x22E10: mov      eax, dword ptr [rsp + 0xd0]
0x22E17: mov      dword ptr [rsp + 0x20], eax
0x22E1B: lea      r9, [rsp + 0xc8]
0x22E23: mov      r8d, r13d
0x22E26: mov      edx, r14d
0x22E29: mov      rcx, r12
0x22E2C: call     0x119c8
0x22E31: cmp      eax, 2
0x22E34: jne      0x22e5f
0x22E36: movzx    ecx, word ptr [rsp + 0xc8]
0x22E3E: bt       cx, 0xf
0x22E43: jb       0x22e67
0x22E45: mov      eax, dword ptr [rsp + 0x98]
0x22E4C: add      eax, 1
0x22E4F: mov      dword ptr [rsp + 0x98], eax
0x22E56: cmp      eax, 0x200
0x22E5B: jb       0x22e08
0x22E5D: jmp      0x22e67
0x22E5F: mov      cx, word ptr [rsp + 0xc8]
0x22E67: mov      ax, cx
0x22E6A: not      eax
0x22E6C: bt       eax, 0xf
0x22E70: jb       0x22ec2
0x22E72: mov      ecx, dword ptr [rsp + 0xa0]
0x22E79: add      ecx, 4
0x22E7C: mov      eax, ebx
0x22E7E: shr      rax, 2
0x22E82: lea      r9, [rdi + rax*4]
0x22E86: mov      dword ptr [rsp + 0x28], 4
0x22E8E: mov      dword ptr [rsp + 0x20], ecx
0x22E92: mov      r8d, r13d
0x22E95: mov      edx, r14d
0x22E98: mov      rcx, r12
0x22E9B: call     0x119c8
0x22EA0: cmp      eax, 4
0x22EA3: jne      0x22ec2
0x22EA5: add      ebx, eax
0x22EA7: mov      dword ptr [rsp + 0x9c], ebx
0x22EAE: cmp      ebx, dword ptr [rsp + 0x94]
0x22EB5: mov      ecx, dword ptr [rsp + 0xd0]
0x22EBC: jb       0x22dc7
0x22EC2: mov      eax, ebx
0x22EC4: mov      qword ptr [r15 + 0x38], rax
0x22EC8: mov      dword ptr [rsp + 0x90], esi
0x22ECF: jmp      0x28e31
0x22ED4: mov      dword ptr [rsp + 0x90], 0xc000000d
0x22EDF: jmp      0x28e31
0x22EE4: test     bl, 3
0x22EE7: jne      0x28e31
0x22EED: cmp      ebx, r8d
0x22EF0: jb       0x28e31
0x22EF6: cmp      r13d, ebx
0x22EF9: jb       0x28e31
0x22EFF: mov      edx, dword ptr [r14]
0x22F02: mov      dword ptr [rsp + 0xd8], edx
0x22F09: cmp      edx, 0xff
0x22F0F: ja       0x28e31
0x22F15: mov      r8d, dword ptr [r14 + 4]
0x22F19: cmp      r8d, 0xff
0x22F20: ja       0x28e31
0x22F26: mov      eax, dword ptr [r14 + 8]
0x22F2A: cmp      eax, 0xfc
0x22F2F: ja       0x28e31
0x22F35: lea      r9, [r14 + 0xc]
0x22F39: mov      dword ptr [rsp + 0x28], 4
0x22F41: mov      dword ptr [rsp + 0x20], eax
0x22F45: mov      rcx, r12
0x22F48: call     0x11ae4
0x22F4D: add      eax, 0xc
0x22F50: mov      qword ptr [r15 + 0x38], rax
0x22F54: mov      dword ptr [rsp + 0x90], esi
0x22F5B: jmp      0x28e31
0x22F60: cmp      ebx, 0xc  ← IOCTL 0x0C (WRMSR)
0x22F63: jb       0x28e31
0x22F69: test     bl, 3
0x22F6C: jne      0x28e31
0x22F72: cmp      r13d, 4
0x22F76: jb       0x28e31
0x22F7C: test     r13b, 3
0x22F80: jne      0x28e31
0x22F86: mov      edx, dword ptr [r14]
0x22F89: mov      dword ptr [rsp + 0xb0], edx
0x22F90: mov      dword ptr [rsp + 0xd8], edx
0x22F97: mov      r8d, dword ptr [r14 + 4]
0x22F9B: mov      dword ptr [rsp + 0xd0], r8d
0x22FA3: add      r14, 8
0x22FA7: mov      eax, dword ptr [r14]
0x22FAA: mov      dword ptr [rsp + 0xa0], eax
0x22FB1: test     al, 3
0x22FB3: jne      0x28e31
0x22FB9: mov      ecx, 0x1000
0x22FBE: cmp      eax, ecx
0x22FC0: jae      0x28e31
0x22FC6: sub      ecx, eax
0x22FC8: cmp      r13d, ecx
0x22FCB: cmovb    ecx, r13d
0x22FCF: mov      dword ptr [rsp + 0x94], ecx
0x22FD6: cmp      dword ptr [r12 + 0x70], 0xa
0x22FDC: jae      0x2316e
0x22FE2: mov      r13d, 0x100
0x22FE8: cmp      eax, r13d
0x22FEB: jae      0x22ff8
0x22FED: add      eax, ecx
0x22FEF: cmp      eax, r13d
0x22FF2: jbe      0x23167
0x22FF8: mov      dword ptr [rsp + 0x90], esi
0x22FFF: mov      r9d, dword ptr [r12 + 0x11ac]
0x23007: mov      rcx, r12
0x2300A: call     0x29944
0x2300F: mov      rdx, rax
0x23012: mov      qword ptr [rsp + 0x130], rax
0x2301A: cmp      rax, rsi
0x2301D: je       0x23117
0x23023: mov      r13d, 0x10
0x23029: cmp      ebx, r13d
0x2302C: jb       0x2308c
0x2302E: mov      qword ptr [rsp + 0x158], r14
0x23036: add      ebx, -8
0x23039: add      rbx, r14
0x2303C: mov      qword ptr [rsp + 0x150], rbx
0x23044: cmp      r14, rbx
0x23047: jae      0x2308c
0x23049: mov      eax, dword ptr [r14]
0x2304C: mov      dword ptr [rsp + 0x98], eax
0x23053: add      r14, 4
0x23057: mov      qword ptr [rsp + 0x158], r14
0x2305F: cmp      eax, 0xfff
0x23064: ja       0x23081
0x23066: test     al, 3
0x23068: jne      0x23081
0x2306A: mov      rcx, rax
0x2306D: mov      eax, dword ptr [r14]
0x23070: mov      dword ptr [rcx + rdx], eax
0x23073: add      r14, 4
0x23077: mov      qword ptr [rsp + 0x158], r14
0x2307F: jmp      0x23044
0x23081: mov      dword ptr [rsp + 0x90], 0xc0000119
0x2308C: mov      ecx, dword ptr [rsp + 0xa0]
0x23093: add      rcx, rdx
0x23096: mov      qword ptr [rsp + 0x158], rcx
0x2309E: mov      eax, dword ptr [rsp + 0x94]
0x230A5: lea      rbx, [rcx + rax]
0x230A9: mov      qword ptr [rsp + 0x150], rbx
0x230B1: cmp      rcx, rbx
0x230B4: jae      0x230db
0x230B6: mov      eax, dword ptr [rcx]
0x230B8: mov      dword ptr [rdi], eax
0x230BA: add      rdi, 4
0x230BE: mov      qword ptr [rsp + 0x138], rdi
0x230C6: add      rcx, 4
0x230CA: mov      qword ptr [rsp + 0x158], rcx
0x230D2: mov      eax, dword ptr [rsp + 0x94]
0x230D9: jmp      0x230b1
0x230DB: mov      qword ptr [r15 + 0x38], rax
0x230DF: jmp      0x23102
0x230E1: mov      dword ptr [rsp + 0x90], eax
0x230E8: xor      esi, esi
0x230EA: mov      r12, qword ptr [rsp + 0xe0]
0x230F2: mov      rdx, qword ptr [rsp + 0x130]
0x230FA: mov      r15, qword ptr [rsp + 0xe8]
0x23102: mov      r8d, dword ptr [r12 + 0x11ac]
0x2310A: mov      rcx, r12
0x2310D: call     0x29c2c
0x23112: jmp      0x28e31
0x23117: mov      ecx, dword ptr [rsp + 0xa0]
0x2311E: cmp      ecx, r13d
0x23121: jb       0x23133
0x23123: mov      dword ptr [rsp + 0x90], 0xc00000e6
0x2312E: jmp      0x28e31
0x23133: mov      eax, dword ptr [rsp + 0x94]
0x2313A: mov      dword ptr [rsp + 0x28], eax
0x2313E: mov      dword ptr [rsp + 0x20], ecx
0x23142: mov      r9, rdi
0x23145: mov      r8d, dword ptr [rsp + 0xd0]
0x2314D: mov      edx, dword ptr [rsp + 0xb0]
0x23154: mov      rcx, r12
0x23157: call     0x119c8
0x2315C: mov      edx, eax
0x2315E: mov      qword ptr [r15 + 0x38], rdx
0x23162: jmp      0x28e31
0x23167: mov      eax, dword ptr [rsp + 0xa0]
0x2316E: cmp      ebx, 0x14  ← IOCTL 0x14 (PhysMem_Map)
0x23171: jne      0x23225
0x23177: mov      ebx, 0x90
0x2317C: cmp      eax, ebx
0x2317E: jne      0x23225
0x23184: lea      r9, [rdi + 0xc]
0x23188: mov      dword ptr [rsp + 0x28], 8
0x23190: mov      dword ptr [rsp + 0x20], ebx
0x23194: mov      rcx, r12
0x23197: call     0x11ae4
0x2319C: mov      r14d, esi
0x2319F: mov      dword ptr [rsp + 0x9c], esi
0x231A6: mov      r13d, dword ptr [rsp + 0xb0]
0x231AE: mov      eax, dword ptr [rsp + 0x94]
0x231B5: mov      dword ptr [rsp + 0x28], eax
0x231B9: mov      dword ptr [rsp + 0x20], ebx
0x231BD: mov      r9, rdi
0x231C0: mov      r8d, dword ptr [rsp + 0xd0]
0x231C8: mov      edx, r13d
0x231CB: mov      rcx, r12
0x231CE: call     0x119c8
0x231D3: cmp      eax, esi
0x231D5: je       0x23213
0x231D7: mov      eax, dword ptr [rdi + 4]
0x231DA: not      eax
0x231DC: bt       eax, 0x17
0x231E0: jb       0x23213
0x231E2: mov      ecx, 0x19
0x231E7: call     qword ptr [rip - 0xe1d5]  ; → KeStallExecutionProcessor
0x231ED: add      r14d, 1
0x231F1: mov      dword ptr [rsp + 0x9c], r14d
0x231F9: cmp      r14d, 0x64
0x231FD: jb       0x231ae
0x231FF: mov      ecx, dword ptr [rsp + 0x94]
0x23206: mov      edx, r13d
0x23209: mov      r8d, dword ptr [rsp + 0xd0]
0x23211: jmp      0x23225
0x23213: mov      ecx, dword ptr [rsp + 0x94]
0x2321A: mov      edx, r13d
0x2321D: mov      r8d, dword ptr [rsp + 0xd0]
0x23225: mov      dword ptr [rsp + 0x28], ecx
0x23229: mov      ecx, dword ptr [rsp + 0xa0]
0x23230: mov      dword ptr [rsp + 0x20], ecx
0x23234: mov      r9, rdi
0x23237: mov      rcx, r12
0x2323A: call     0x119c8
0x2323F: mov      edx, eax
0x23241: mov      qword ptr [r15 + 0x38], rdx
0x23245: mov      dword ptr [rsp + 0x90], esi
0x2324C: jmp      0x28e31
0x23251: cmp      ebx, 8  ← IOCTL 0x08 (RDMSR)
0x23254: jb       0x28e31
0x2325A: cmp      r13d, eax
0x2325D: jb       0x28e31
0x23263: mov      r14d, dword ptr [r14]
0x23266: mov      dword ptr [rsp + 0xd8], r14d
0x2326E: mov      r8d, dword ptr [rdi + 4]
0x23272: mov      dword ptr [rsp + 0x9c], r8d
0x2327A: cmp      ebx, 0xc  ← IOCTL 0x0C (WRMSR)
0x2327D: jbe      0x2328f
0x2327F: mov      r9d, dword ptr [rdi + 0xc]
0x23283: mov      ebx, dword ptr [rdi + 8]
0x23286: mov      dword ptr [rsp + 0xb0], ebx
0x2328D: jmp      0x232ac
0x2328F: mov      r9d, esi
0x23292: cmp      ebx, 8  ← IOCTL 0x08 (RDMSR)
0x23295: jbe      0x232a3
0x23297: mov      ebx, dword ptr [rdi + 8]
0x2329A: mov      dword ptr [rsp + 0xb0], ebx
0x232A1: jmp      0x232ac
0x232A3: mov      ebx, esi
0x232A5: mov      dword ptr [rsp + 0xb0], ebx
0x232AC: mov      ecx, 0x1000
0x232B1: cmp      ebx, ecx
0x232B3: jae      0x28e31
0x232B9: test     bl, 3
0x232BC: jne      0x28e31
0x232C2: sub      ecx, ebx
0x232C4: cmp      r13d, ecx
0x232C7: cmovb    ecx, r13d
0x232CB: mov      dword ptr [rsp + 0x94], ecx
0x232D2: cmp      r14d, 0x1ff
0x232D9: jbe      0x234f4
0x232DF: cmp      dword ptr [r12 + 0x78], 0x4a61
0x232E8: jae      0x234e8
0x232EE: mov      qword ptr [rsp + 0x100], rsi
0x232F6: mov      eax, r14d
0x232F9: shr      eax, 0x10
0x232FC: mov      dword ptr [rsp + 0xa0], eax
0x23303: mov      dword ptr [rsp + 0xbc], eax
0x2330A: movzx    r13d, r14b
0x2330E: shl      r13d, 4
0x23312: mov      eax, r14d
0x23315: and      eax, 0xffffff00
0x2331A: or       r13d, eax
0x2331D: add      r13d, r13d
0x23320: mov      eax, r8d
0x23323: and      eax, 0x1f
0x23326: or       r13d, eax
0x23329: shl      r13d, 8
0x2332D: mov      eax, r8d
0x23330: and      eax, 0xe0
0x23335: or       r13d, eax
0x23338: shl      r13d, 7
0x2333C: mov      dword ptr [rsp + 0xb8], r13d
0x23344: lea      r8d, [rbx + rcx]
0x23348: mov      rdx, qword ptr [rsp + 0xb8]
0x23350: mov      rcx, r12
0x23353: call     0x29a50
0x23358: mov      rdx, rax
0x2335B: mov      qword ptr [rsp + 0x100], rax
0x23363: cmp      rax, rsi
0x23366: je       0x23471
0x2336C: cmp      ebx, esi
0x2336E: jne      0x23381
0x23370: cmp      dword ptr [rax], esi
0x23372: je       0x23471
0x23378: cmp      dword ptr [rax], -1
0x2337B: je       0x23471
0x23381: mov      ecx, ebx
0x23383: add      rcx, rax
0x23386: mov      qword ptr [rsp + 0x238], rcx
0x2338E: mov      eax, 0x40
0x23393: test     byte ptr [r12], al
0x23397: je       0x233ea
0x23399: mov      dword ptr [rsp + 0x48], ebx
0x2339D: mov      eax, dword ptr [rsp + 0x94]
0x233A4: mov      dword ptr [rsp + 0x40], eax
0x233A8: mov      qword ptr [rsp + 0x38], rcx
0x233AD: mov      qword ptr [rsp + 0x30], rdx
0x233B2: mov      dword ptr [rsp + 0x28], r13d
0x233B7: mov      eax, dword ptr [rsp + 0xa0]
0x233BE: mov      dword ptr [rsp + 0x20], eax
0x233C2: mov      r9, rdi
0x233C5: lea      r8, [rip + 0x19a14]  ; → L"佉呃彌䥓彖䍐䉉单††††獤⁴瀥†慰⁤〥堸╟㠰⁘洠灡┠⁰猠捲┠⁰氠湥┠㐰⁘漠晦┠㐰੘찀쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䵁彄䍐敉†††灶⁷甥㸠眠扤┠Ⱶ戠摡椠汰┠㈰⁘牯℠‽灯⁬〥堲†瑳⁳〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝䀠〠╸㐰⁘┠⁵㴡┠⁵"
0x233CC: mov      edx, 2
0x233D1: lea      ecx, [rdx + 0x4b]
0x233D4: call     qword ptr [rip - 0xe1fa]  ; → DbgPrintEx
0x233DA: mov      rcx, qword ptr [rsp + 0x238]
0x233E2: mov      rdx, qword ptr [rsp + 0x100]
0x233EA: mov      r8, rdi
0x233ED: mov      qword ptr [rsp + 0x278], rdi
0x233F5: mov      r9d, dword ptr [rsp + 0x94]
0x233FD: mov      rax, r9
0x23400: shr      rax, 2
0x23404: lea      r10, [rdi + rax*4]
0x23408: cmp      r8, r10
0x2340B: jae      0x23434
0x2340D: mov      eax, dword ptr [rcx]
0x2340F: mov      dword ptr [r8], eax
0x23412: add      r8, 4
0x23416: mov      qword ptr [rsp + 0x278], r8
0x2341E: add      rcx, 4
0x23422: mov      qword ptr [rsp + 0x238], rcx
0x2342A: mov      r9d, dword ptr [rsp + 0x94]
0x23432: jmp      0x23408
0x23434: mov      r8d, r9d
0x23437: mov      rcx, r12
0x2343A: call     0x29c2c
0x2343F: cmp      ebx, esi
0x23441: jne      0x2345a
0x23443: movzx    edx, r14b
0x23447: mov      r9, rdi
0x2344A: mov      r8d, dword ptr [rsp + 0x9c]
0x23452: mov      rcx, r12
0x23455: call     0x2a984
0x2345A: mov      eax, dword ptr [rsp + 0x94]
0x23461: mov      qword ptr [r15 + 0x38], rax
0x23465: mov      dword ptr [rsp + 0x90], esi
0x2346C: jmp      0x28e31
0x23471: mov      r8d, dword ptr [rsp + 0x9c]
0x23479: jmp      0x234bb
0x2347B: mov      dword ptr [rsp + 0x90], eax
0x23482: xor      esi, esi
0x23484: mov      r12, qword ptr [rsp + 0xe0]
0x2348C: mov      rdi, qword ptr [rsp + 0x138]
0x23494: mov      ebx, dword ptr [rsp + 0xb0]
0x2349B: mov      r14d, dword ptr [rsp + 0xd8]
0x234A3: mov      r8d, dword ptr [rsp + 0x9c]
0x234AB: mov      r15, qword ptr [rsp + 0xe8]
0x234B3: mov      rdx, qword ptr [rsp + 0x100]
0x234BB: cmp      rdx, rsi
0x234BE: je       0x234e1
0x234C0: mov      r8d, dword ptr [rsp + 0x94]
0x234C8: mov      rcx, r12
0x234CB: call     0x29c2c
0x234D0: mov      ecx, dword ptr [rsp + 0x94]
0x234D7: mov      r8d, dword ptr [rsp + 0x9c]
0x234DF: jmp      0x234e8
0x234E1: mov      ecx, dword ptr [rsp + 0x94]
0x234E8: movzx    r14d, r14b
0x234EC: mov      dword ptr [rsp + 0xd8], r14d
0x234F4: mov      dword ptr [rsp + 0x28], ecx
0x234F8: mov      dword ptr [rsp + 0x20], ebx
0x234FC: mov      r9, rdi
0x234FF: mov      edx, r14d
0x23502: mov      rcx, r12
0x23505: call     0x119c8
0x2350A: mov      edx, eax
0x2350C: mov      qword ptr [r15 + 0x38], rdx
0x23510: cmp      ebx, esi
0x23512: jne      0x2352b
0x23514: movzx    edx, r14b
0x23518: mov      r9, rdi
0x2351B: mov      r8d, dword ptr [rsp + 0x9c]
0x23523: mov      rcx, r12
0x23526: call     0x2a984
0x2352B: mov      dword ptr [rsp + 0x90], esi
0x23532: jmp      0x28e31
0x23537: mov      eax, esi
0x23539: xchg     dword ptr [r12 + 0x64], eax
0x2353E: neg      eax
0x23540: lock xadd dword ptr [r12 + 0x5c], eax
0x23547: mov      dword ptr [r12 + 0x60], esi
0x2354C: mov      dword ptr [r12 + 0x54], esi
0x23551: mov      dword ptr [r12 + 0x58], esi
0x23556: mov      dword ptr [r12 + 0x30], esi
0x2355B: mov      dword ptr [r12 + 0x38], esi
0x23560: mov      eax, esi
0x23562: xchg     dword ptr [r12 + 0x6c], eax
0x23567: neg      eax
0x23569: lock xadd dword ptr [r12 + 0x68], eax
0x23570: mov      qword ptr [r15 + 0x38], rsi
0x23574: mov      dword ptr [rsp + 0x90], esi
0x2357B: jmp      0x28e31
0x23580: cmp      ebx, 8  ← IOCTL 0x08 (RDMSR)
0x23583: jb       0x28e31
0x23589: cmp      r13d, 4
0x2358D: jb       0x28e31
0x23593: mov      dword ptr [rsp + 0x28], r13d
0x23598: mov      dword ptr [rsp + 0x20], esi
0x2359C: mov      r9, r14
0x2359F: mov      r8d, dword ptr [r14 + 4]
0x235A3: mov      edx, dword ptr [r14]
0x235A6: mov      ecx, 7
0x235AB: call     qword ptr [rip - 0xe5a9]  ; → HalGetBusDataByOffset
0x235B1: mov      dword ptr [rsp + 0x9c], eax
0x235B8: mov      eax, eax
0x235BA: mov      qword ptr [r15 + 0x38], rax
0x235BE: mov      dword ptr [rsp + 0x90], esi
0x235C5: jmp      0x28e31
0x235CA: cmp      edx, 0x58
0x235CD: je       0x23aac
0x235D3: cmp      edx, 0x5c
0x235D6: je       0x23a2c
0x235DC: cmp      edx, 0x60
0x235DF: je       0x2394f
0x235E5: cmp      edx, 0x64
0x235E8: je       0x237fc
0x235EE: cmp      edx, 0x68
0x235F1: je       0x236ed
0x235F7: cmp      edx, 0x70
0x235FA: jne      0x28372
0x23600: test     bl, 3
0x23603: jne      0x28e31
0x23609: test     r13b, 3
0x2360D: jne      0x28e31
0x23613: cmp      ebx, 0xc  ← IOCTL 0x0C (WRMSR)
0x23616: jb       0x28e31
0x2361C: lea      rcx, [rbx - 8]
0x23620: mov      eax, r13d
0x23623: cmp      rax, rcx
0x23626: jb       0x28e31
0x2362C: mov      dword ptr [rsp + 0x90], 0xc000000e
0x23637: cmp      dword ptr [r12 + 0x1dc], esi
0x2363F: je       0x28e31
0x23645: mov      r13d, dword ptr [r14]
0x23648: mov      dword ptr [rsp + 0xd8], r13d
0x23650: mov      eax, dword ptr [r14 + 4]
0x23654: add      ebx, -8
0x23657: mov      dword ptr [rsp + 0x94], ebx
0x2365E: cmp      r13d, 0xff
0x23665: ja       0x28e31
0x2366B: add      rbx, r14
0x2366E: cmp      r14, rbx
0x23671: jae      0x236d8
0x23673: mov      r14d, eax
0x23676: lea      r9, [rdi + 8]
0x2367A: mov      dword ptr [rsp + 0x28], 4
0x23682: mov      dword ptr [rsp + 0x20], 0x60
0x2368A: mov      r8d, r14d
0x2368D: mov      edx, r13d
0x23690: mov      rcx, r12
0x23693: call     0x11ae4
0x23698: cmp      eax, 4
0x2369B: jne      0x236d0
0x2369D: mov      dword ptr [rsp + 0x28], eax
0x236A1: mov      dword ptr [rsp + 0x20], 0x64
0x236A9: mov      r9, rdi
0x236AC: mov      r8d, r14d
0x236AF: mov      edx, r13d
0x236B2: mov      rcx, r12
0x236B5: call     0x119c8
0x236BA: cmp      eax, 4
0x236BD: jne      0x236d0
0x236BF: add      rdi, 4
0x236C3: mov      qword ptr [rsp + 0x138], rdi
0x236CB: cmp      rdi, rbx
0x236CE: jb       0x23676
0x236D0: mov      r14, qword ptr [rsp + 0x150]
0x236D8: sub      edi, r14d
0x236DB: mov      eax, edi
0x236DD: mov      qword ptr [r15 + 0x38], rax
0x236E1: mov      dword ptr [rsp + 0x90], esi
0x236E8: jmp      0x28e31
0x236ED: cmp      ebx, 0x20
0x236F0: jb       0x28e31
0x236F6: mov      r14d, dword ptr [r14 + 0xc]
0x236FA: lea      rcx, [r14 + 0x20]
0x236FE: cmp      rbx, rcx
0x23701: jb       0x28e31
0x23707: cmp      r13d, 0x20
0x2370B: jb       0x28e31
0x23711: mov      r13d, dword ptr [rdi + 8]
0x23715: mov      ecx, dword ptr [rdi + 4]
0x23718: mov      dword ptr [rsp + 0xa0], ecx
0x2371F: mov      ebx, dword ptr [rdi]
0x23721: mov      dword ptr [rsp + 0xd8], ebx
0x23728: mov      qword ptr [rsp + 0x30], rdi
0x2372D: mov      eax, dword ptr [rdi + 0x10]
0x23730: mov      dword ptr [rsp + 0x28], eax
0x23734: mov      dword ptr [rsp + 0x20], r14d
0x23739: mov      r9b, r13b
0x2373C: mov      r8b, cl
0x2373F: mov      edx, ebx
0x23741: mov      rcx, r12
0x23744: call     0x306b0
0x23749: mov      ecx, eax
0x2374B: mov      dword ptr [rsp + 0x90], eax
0x23752: cmp      eax, esi
0x23754: jl       0x237a4
0x23756: mov      eax, 0x80
0x2375B: test     byte ptr [r12], al
0x2375F: je       0x23797
0x23761: mov      dword ptr [rsp + 0x38], r14d
0x23766: mov      dword ptr [rsp + 0x30], r13d
0x2376B: mov      eax, dword ptr [rsp + 0xa0]
0x23772: mov      dword ptr [rsp + 0x28], eax
0x23776: mov      dword ptr [rsp + 0x20], ebx
0x2377A: mov      r9, qword ptr [rsp + 0xb8]
0x23782: lea      r8, [rip + 0x19967]  ; → L"佉呃彌䥓彖䵓偂呕††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭〥場
쳌쳌쳌쳌쳌佉呃彌䥓彖䵓偂呕††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭〥場†瑳⁳〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘洠灡┠⁰倠潲敢੤"
0x23789: mov      edx, 2
0x2378E: lea      ecx, [rdx + 0x4b]
0x23791: call     qword ptr [rip - 0xe5b7]  ; → DbgPrintEx
0x23797: mov      qword ptr [r15 + 0x38], 0x20
0x2379F: jmp      0x28e31
0x237A4: mov      eax, 0x80
0x237A9: test     byte ptr [r12], al
0x237AD: je       0x28e31
0x237B3: call     0x12acc
0x237B8: mov      qword ptr [rsp + 0x48], rax
0x237BD: mov      dword ptr [rsp + 0x40], ecx
0x237C1: mov      dword ptr [rsp + 0x38], r14d
0x237C6: mov      dword ptr [rsp + 0x30], r13d
0x237CB: mov      eax, dword ptr [rsp + 0xa0]
0x237D2: mov      dword ptr [rsp + 0x28], eax
0x237D6: mov      dword ptr [rsp + 0x20], ebx
0x237DA: mov      r9d, dword ptr [rsp + 0x94]
0x237E2: lea      r8, [rip + 0x19957]  ; → L"佉呃彌䥓彖䵓偂呕††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭〥場†瑳⁳〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘洠灡┠⁰倠潲敢੤찀쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䥂彇䕍位奒††湩⁰瀥┠㠰⁘漠瑵┠⁰〥堸†慰⁤〥堸╟㠰⁘"
0x237E9: mov      edx, 2
0x237EE: lea      ecx, [rdx + 0x4b]
0x237F1: call     qword ptr [rip - 0xe617]  ; → DbgPrintEx
0x237F7: jmp      0x28e31
0x237FC: cmp      ebx, 0x20
0x237FF: jb       0x28e31
0x23805: mov      ebx, dword ptr [r14 + 0xc]
0x23809: lea      rcx, [rbx + 0x20]
0x2380D: mov      eax, r13d
0x23810: cmp      rax, rcx
0x23813: jb       0x28e31
0x23819: mov      edx, dword ptr [r14 + 8]
0x2381D: mov      dword ptr [rsp + 0xa0], edx
0x23824: mov      r8d, dword ptr [r14 + 4]
0x23828: mov      dword ptr [rsp + 0xd0], r8d
0x23830: mov      r14d, dword ptr [r14]
0x23833: mov      dword ptr [rsp + 0xd8], r14d
0x2383B: mov      eax, dword ptr [rdi + 0x10]
0x2383E: cmp      ebx, 0x100
0x23844: ja       0x23891
0x23846: lea      rcx, [rsp + 0x94]
0x2384E: mov      qword ptr [rsp + 0x38], rcx
0x23853: mov      qword ptr [rsp + 0x30], rdi
0x23858: mov      dword ptr [rsp + 0x28], eax
0x2385C: mov      dword ptr [rsp + 0x20], ebx
0x23860: mov      r9b, dl
0x23863: mov      edx, r14d
0x23866: mov      rcx, r12
0x23869: call     0x3050c
0x2386E: mov      r11d, eax
0x23871: mov      dword ptr [rsp + 0x90], eax
0x23878: mov      r13d, dword ptr [rsp + 0x94]
0x23880: mov      edx, dword ptr [rsp + 0xa0]
0x23887: mov      r8d, dword ptr [rsp + 0xd0]
0x2388F: jmp      0x2389f
0x23891: mov      r11d, 0xc000009d
0x23897: mov      dword ptr [rsp + 0x90], r11d
0x2389F: cmp      r11d, esi
0x238A2: jl       0x238fa
0x238A4: mov      eax, 0x80
0x238A9: test     byte ptr [r12], al
0x238AD: je       0x238ee
0x238AF: mov      dword ptr [rsp + 0x48], r13d
0x238B4: mov      dword ptr [rsp + 0x40], r13d
0x238B9: mov      dword ptr [rsp + 0x38], ebx
0x238BD: mov      dword ptr [rsp + 0x30], edx
0x238C1: mov      dword ptr [rsp + 0x28], r8d
0x238C6: mov      dword ptr [rsp + 0x20], r14d
0x238CB: mov      r9, qword ptr [rsp + 0xb8]
0x238D3: lea      r8, [rip + 0x19756]  ; → L"佉呃彌䥓彖䵓䝂呅††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭〥場†敬⁮〥場⠠甥਩찀쳌쳌쳌쳌쳌佉呃彌䥓彖䵓䝂呅††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭〥場†瑳⁳〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䵓偂呕††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭"
0x238DA: lea      edx, [rax - 0x7e]
0x238DD: lea      ecx, [rax - 0x33]
0x238E0: call     qword ptr [rip - 0xe706]  ; → DbgPrintEx
0x238E6: mov      r13d, dword ptr [rsp + 0x94]
0x238EE: mov      eax, r13d
0x238F1: mov      qword ptr [r15 + 0x38], rax
0x238F5: jmp      0x28e31
0x238FA: mov      eax, 0x80
0x238FF: test     byte ptr [r12], al
0x23903: je       0x28e31
0x23909: mov      ecx, r11d
0x2390C: call     0x12acc
0x23911: mov      qword ptr [rsp + 0x48], rax
0x23916: mov      dword ptr [rsp + 0x40], r11d
0x2391B: mov      dword ptr [rsp + 0x38], ebx
0x2391F: mov      dword ptr [rsp + 0x30], edx
0x23923: mov      dword ptr [rsp + 0x28], r8d
0x23928: mov      dword ptr [rsp + 0x20], r14d
0x2392D: mov      r9, qword ptr [rsp + 0xb8]
0x23935: lea      r8, [rip + 0x19754]  ; → L"佉呃彌䥓彖䵓䝂呅††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭〥場†瑳⁳〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䵓偂呕††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭〥場
쳌쳌쳌쳌쳌佉呃彌䥓彖䵓偂呕††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭〥場†瑳⁳〥堸猥"
0x2393C: mov      edx, 2
0x23941: lea      ecx, [rdx + 0x4b]
0x23944: call     qword ptr [rip - 0xe76a]  ; → DbgPrintEx
0x2394A: jmp      0x28e31
0x2394F: cmp      ebx, 0x114
0x23955: jne      0x23992
0x23957: lea      rax, [r14 + 0x14]
0x2395B: mov      qword ptr [rsp + 0x30], rax
0x23960: mov      eax, dword ptr [r14 + 0x10]
0x23964: mov      dword ptr [rsp + 0x28], eax
0x23968: mov      eax, dword ptr [r14 + 0xc]
0x2396C: mov      dword ptr [rsp + 0x20], eax
0x23970: mov      r9d, dword ptr [r14 + 8]
0x23974: mov      r8d, dword ptr [r14 + 4]
0x23978: mov      edx, dword ptr [r14]
0x2397B: mov      rcx, r12
0x2397E: call     0x2bd00
0x23983: mov      dword ptr [rsp + 0x90], esi
0x2398A: mov      r13d, dword ptr [rsp + 0x94]
0x23992: movsxd   rcx, dword ptr [r12 + 0x11d4]
0x2399A: mov      r8d, r13d
0x2399D: mov      rax, rcx
0x239A0: imul     rax, rax, 0x68
0x239A4: cmp      r8, rax
0x239A7: jb       0x28e31
0x239AD: cmp      ecx, esi
0x239AF: je       0x23a1c
0x239B1: xor      edx, edx
0x239B3: mov      rcx, r14
0x239B6: call     0x13580
0x239BB: lea      rbx, [r12 + 0x11e0]
0x239C3: movsxd   r13, dword ptr [r12 + 0x11d4]
0x239CB: shl      r13, 8
0x239CF: add      r13, rbx
0x239D2: cmp      rbx, r13
0x239D5: jae      0x23a00
0x239D7: mov      rcx, rdi
0x239DA: mov      rdx, rbx
0x239DD: mov      r8d, 0x68
0x239E3: call     0x12e10
0x239E8: add      rdi, 0x68
0x239EC: add      rbx, 0x100
0x239F3: cmp      rbx, r13
0x239F6: jb       0x239d7
0x239F8: mov      qword ptr [rsp + 0x138], rdi
0x23A00: movsxd   rax, dword ptr [r12 + 0x11d4]
0x23A08: imul     rax, rax, 0x68
0x23A0C: mov      qword ptr [r15 + 0x38], rax
0x23A10: mov      dword ptr [rsp + 0x90], esi
0x23A17: jmp      0x28e31
0x23A1C: mov      dword ptr [rsp + 0x90], 0xc0000225
0x23A27: jmp      0x28e31
0x23A2C: cmp      ebx, 8  ← IOCTL 0x08 (RDMSR)
0x23A2F: jb       0x28e31
0x23A35: mov      ebx, 0x80
0x23A3A: cmp      r13d, ebx
0x23A3D: jb       0x28e31
0x23A43: mov      dword ptr [rsp + 0x28], r13d
0x23A48: mov      dword ptr [rsp + 0x20], esi
0x23A4C: mov      r9, r14
0x23A4F: mov      r8d, dword ptr [r14 + 4]
0x23A53: mov      edx, dword ptr [r14]
0x23A56: xor      ecx, ecx
0x23A58: call     qword ptr [rip - 0xea56]  ; → HalGetBusDataByOffset
0x23A5E: mov      r11d, eax
0x23A61: mov      dword ptr [rsp + 0x9c], eax
0x23A68: cmp      eax, esi
0x23A6A: jne      0x23a99
0x23A6C: mov      r11d, esi
0x23A6F: mov      dx, 0x70
0x23A73: mov      al, r11b
0x23A76: out      dx, al
0x23A77: in       al, 0x71
0x23A79: mov      byte ptr [r14], al
0x23A7C: add      r14, 1
0x23A80: add      r11d, 1
0x23A84: cmp      r11d, ebx
0x23A87: jb       0x23a6f
0x23A89: mov      qword ptr [rsp + 0x148], r14
0x23A91: mov      dword ptr [rsp + 0x9c], r11d
0x23A99: mov      eax, r11d
0x23A9C: mov      qword ptr [r15 + 0x38], rax
0x23AA0: mov      dword ptr [rsp + 0x90], esi
0x23AA7: jmp      0x28e31
0x23AAC: cmp      ebx, 8  ← IOCTL 0x08 (RDMSR)
0x23AAF: jb       0x28e31
0x23AB5: cmp      r13d, 0xc  ← IOCTL 0x0C (WRMSR)
0x23AB9: jb       0x28e31
0x23ABF: mov      dword ptr [rsp + 0x28], r13d
0x23AC4: mov      dword ptr [rsp + 0x20], esi
0x23AC8: mov      r9, r14
0x23ACB: mov      r8d, dword ptr [r14 + 4]
0x23ACF: mov      edx, dword ptr [r14]
0x23AD2: mov      ecx, 1
0x23AD7: call     qword ptr [rip - 0xead5]  ; → HalGetBusDataByOffset
0x23ADD: mov      dword ptr [rsp + 0x9c], eax
0x23AE4: mov      eax, eax
0x23AE6: mov      qword ptr [r15 + 0x38], rax
0x23AEA: mov      dword ptr [rsp + 0x90], esi
0x23AF1: jmp      0x28e31
0x23AF6: test     bl, 3
0x23AF9: jne      0x28e31
0x23AFF: cmp      ebx, 0x48  ← IOCTL 0x48 (PCI_Read)
0x23B02: jb       0x28e31
0x23B08: test     r13b, 3
0x23B0C: jne      0x28e31
0x23B12: cmp      r13d, 0x48  ← IOCTL 0x48 (PCI_Read)
0x23B16: jb       0x28e31
0x23B1C: mov      dword ptr [rsp + 0x90], 0xc000000e
0x23B27: cmp      qword ptr [r12 + 0x1e0], rsi
0x23B2F: je       0x28e31
0x23B35: cmp      qword ptr [r12 + 0x1e8], rsi
0x23B3D: je       0x28e31
0x23B43: mov      rdx, r14
0x23B46: mov      rcx, r12
0x23B49: call     0x2ae04
0x23B4E: mov      dword ptr [rsp + 0x94], eax
0x23B55: cmp      eax, esi
0x23B57: je       0x23b6b
0x23B59: mov      eax, eax
0x23B5B: mov      qword ptr [r15 + 0x38], rax
0x23B5F: mov      dword ptr [rsp + 0x90], esi
0x23B66: jmp      0x28e31
0x23B6B: mov      dword ptr [rsp + 0x90], 0xc0000185
0x23B76: jmp      0x28e31
0x23B7B: mov      eax, 0xb0
0x23B80: cmp      edx, eax
0x23B82: ja       0x2491e
0x23B88: cmp      edx, eax
0x23B8A: je       0x248e6
0x23B90: mov      eax, 0x90
0x23B95: cmp      edx, eax
0x23B97: ja       0x2456f
0x23B9D: cmp      edx, eax
0x23B9F: je       0x2450d
0x23BA5: mov      eax, edx
0x23BA7: sub      eax, 0x78
0x23BAA: je       0x244a2
0x23BB0: sub      eax, 4
0x23BB3: je       0x243b5
0x23BB9: sub      eax, 4
0x23BBC: je       0x2420c
0x23BC2: sub      eax, 4
0x23BC5: je       0x23d7a
0x23BCB: sub      eax, 4
0x23BCE: je       0x23d17
0x23BD4: cmp      eax, 4
0x23BD7: jne      0x28372
0x23BDD: cmp      ebx, eax
0x23BDF: jne      0x23c22
0x23BE1: mov      ebx, 0x100000
0x23BE6: mov      r9d, ebx
0x23BE9: xor      r8d, r8d
0x23BEC: mov      edx, dword ptr [r14]
0x23BEF: mov      rcx, r12
0x23BF2: call     0x29944
0x23BF7: mov      qword ptr [rsp + 0x100], rax
0x23BFF: cmp      rax, rsi
0x23C02: je       0x23c12
0x23C04: mov      r8, rbx
0x23C07: mov      rdx, rax
0x23C0A: mov      rcx, r12
0x23C0D: call     0x29c2c
0x23C12: mov      qword ptr [r15 + 0x38], rsi
0x23C16: mov      dword ptr [rsp + 0x90], esi
0x23C1D: jmp      0x28e31
0x23C22: cmp      ebx, esi
0x23C24: je       0x23cc1
0x23C2A: mov      r9d, 0x18
0x23C30: cmp      ebx, r9d
0x23C33: jne      0x28e31
0x23C39: cmp      dword ptr [r12 + 0x11a8], 1
0x23C42: jne      0x28e31
0x23C48: cmp      qword ptr [r12 + 0x2df0], rsi
0x23C50: jne      0x28e31
0x23C56: mov      eax, dword ptr [r14]
0x23C59: cmp      dword ptr [r12 + 0x2de0], eax
0x23C61: jne      0x28e31
0x23C67: mov      eax, dword ptr [r14 + 8]
0x23C6B: cmp      dword ptr [r12 + 0x2de8], eax
0x23C73: jne      0x28e31
0x23C79: mov      eax, dword ptr [r14 + 0xc]
0x23C7D: cmp      dword ptr [r12 + 0x2dec], eax
0x23C85: jb       0x28e31
0x23C8B: cmp      qword ptr [r14 + 0x10], rsi
0x23C8F: je       0x28e31
0x23C95: mov      dword ptr [r12 + 0x2dec], eax
0x23C9D: mov      rax, qword ptr [r14 + 0x10]
0x23CA1: mov      qword ptr [r12 + 0x2df0], rax
0x23CA9: mov      rcx, r12
0x23CAC: call     0x298cc
0x23CB1: mov      qword ptr [r15 + 0x38], rsi
0x23CB5: mov      dword ptr [rsp + 0x90], esi
0x23CBC: jmp      0x28e31
0x23CC1: mov      eax, dword ptr [r12 + 0x11a8]
0x23CC9: lea      ecx, [rax + rax*2]
0x23CCC: shl      ecx, 3
0x23CCF: mov      dword ptr [rsp + 0x98], ecx
0x23CD6: mov      r8d, ecx
0x23CD9: mov      edx, 0x60
0x23CDE: cmp      ecx, edx
0x23CE0: cmova    rdx, r8
0x23CE4: mov      eax, r13d
0x23CE7: cmp      rax, rdx
0x23CEA: jb       0x28e31
0x23CF0: lea      rdx, [r12 + 0x2de0]
0x23CF8: mov      rcx, r14
0x23CFB: call     0x12e10
0x23D00: mov      edx, dword ptr [rsp + 0x98]
0x23D07: mov      qword ptr [r15 + 0x38], rdx
0x23D0B: mov      dword ptr [rsp + 0x90], esi
0x23D12: jmp      0x28e31
0x23D17: lea      rdx, [r12 + 0x258]
0x23D1F: mov      qword ptr [rsp + 0x120], rdx
0x23D27: lea      rax, [rip + 0x1773e]  ; → L"襈⑜䠈沉ဤ襈⑴團呁啁噁坁荈レ䅦碁＜䧿�譈䣺ݵ䅦䃇晠읁Ṁ怀䊋䅌䂉謈偂읁၀耀"
0x23D2E: cmp      qword ptr [rdx + 0x20], rax
0x23D32: je       0x23d4d
0x23D34: bt       dword ptr [r12 + 8], 0x1a
0x23D3B: jb       0x23d4d
0x23D3D: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x23D48: jmp      0x28e31
0x23D4D: cmp      ebx, r8d
0x23D50: jb       0x28e31
0x23D56: cmp      r13d, r8d
0x23D59: jb       0x28e31
0x23D5F: mov      qword ptr [r15 + 0x38], r8
0x23D63: mov      r8, r14
0x23D66: mov      rcx, r12
0x23D69: call     0x3b37c
0x23D6E: mov      dword ptr [rsp + 0x90], eax
0x23D75: jmp      0x28e31
0x23D7A: cmp      r13d, 0x24
0x23D7E: jb       0x28e31
0x23D84: mov      rbx, qword ptr [r15 + 0x18]
0x23D88: mov      r8d, r13d
0x23D8B: xor      edx, edx
0x23D8D: mov      rcx, rbx
0x23D90: call     0x13580
0x23D95: mov      r14w, 0x17
0x23D9A: mov      word ptr [rsp + 0x192], r14w
0x23DA3: mov      word ptr [rsp + 0x190], 0x88
0x23DAD: mov      dword ptr [rsp + 0x1b4], 4
0x23DB8: mov      qword ptr [rsp + 0x1c0], rsi
0x23DC0: mov      qword ptr [rsp + 0x1b8], rbx
0x23DC8: mov      byte ptr [rsp + 0x210], 0xc0
0x23DD0: mov      byte ptr [rsp + 0x211], 1
0x23DD8: mov      word ptr [rsp + 0x212], si
0x23DE0: mov      word ptr [rsp + 0x214], si
0x23DE8: mov      dword ptr [rsp + 0x1b0], 1
0x23DF3: mov      qword ptr [rsp + 0x1c8], rsi
0x23DFB: lea      r8, [rsp + 0x190]
0x23E03: mov      rdi, qword ptr [rsp + 0xc0]
0x23E0B: mov      rdx, rdi
0x23E0E: mov      rcx, r12
0x23E11: call     0x3c6f4
0x23E16: mov      ecx, eax
0x23E18: mov      dword ptr [rsp + 0x90], eax
0x23E1F: cmp      eax, esi
0x23E21: jl       0x241d9
0x23E27: bt       dword ptr [r12], 0xb
0x23E2D: jae      0x23e47
0x23E2F: mov      r9d, dword ptr [rbx]
0x23E32: lea      r8, [rip + 0x19f47]  ; → L"佉呃彌䥓彖塏䕓䥍›灵㸭䑶癥††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭䑶癥††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭䙶硩††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭䙶硩††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭祴数††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍"
0x23E39: mov      edx, 2
0x23E3E: lea      ecx, [rdx + 0x4b]
0x23E41: call     qword ptr [rip - 0xec67]  ; → DbgPrintEx
0x23E47: mov      word ptr [rsp + 0x192], r14w
0x23E50: mov      word ptr [rsp + 0x190], 0x88
0x23E5A: mov      dword ptr [rsp + 0x1b4], 4
0x23E65: mov      qword ptr [rsp + 0x1c0], rsi
0x23E6D: lea      r13, [rbx + 4]
0x23E71: mov      qword ptr [rsp + 0x1b8], r13
0x23E79: mov      byte ptr [rsp + 0x210], 0xc0
0x23E81: mov      byte ptr [rsp + 0x211], 1
0x23E89: mov      word ptr [rsp + 0x212], si
0x23E91: mov      word ptr [rsp + 0x214], 1
0x23E9B: mov      dword ptr [rsp + 0x1b0], 1
0x23EA6: mov      qword ptr [rsp + 0x1c8], rsi
0x23EAE: lea      r8, [rsp + 0x190]
0x23EB6: mov      rdx, rdi
0x23EB9: mov      rcx, r12
0x23EBC: call     0x3c6f4
0x23EC1: mov      ecx, eax
0x23EC3: mov      dword ptr [rsp + 0x90], eax
0x23ECA: cmp      eax, esi
0x23ECC: jl       0x241a6
0x23ED2: bt       dword ptr [r12], 0xb
0x23ED8: jae      0x23ef3
0x23EDA: mov      r9d, dword ptr [r13]
0x23EDE: lea      r8, [rip + 0x19efb]  ; → L"佉呃彌䥓彖塏䕓䥍›灵㸭䙶硩††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭䙶硩††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭祴数††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭祴数††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭慤整††簠⸥猪੼찀쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍"
0x23EE5: mov      edx, 2
0x23EEA: lea      ecx, [rdx + 0x4b]
0x23EED: call     qword ptr [rip - 0xed13]  ; → DbgPrintEx
0x23EF3: mov      word ptr [rsp + 0x192], r14w
0x23EFC: mov      word ptr [rsp + 0x190], 0x88
0x23F06: mov      dword ptr [rsp + 0x1b4], 4
0x23F11: mov      qword ptr [rsp + 0x1c0], rsi
0x23F19: lea      r13, [rbx + 8]
0x23F1D: mov      qword ptr [rsp + 0x1b8], r13
0x23F25: mov      byte ptr [rsp + 0x210], 0xc0
0x23F2D: mov      byte ptr [rsp + 0x211], 2
0x23F35: mov      word ptr [rsp + 0x212], si
0x23F3D: mov      word ptr [rsp + 0x214], si
0x23F45: mov      dword ptr [rsp + 0x1b0], 1
0x23F50: mov      qword ptr [rsp + 0x1c8], rsi
0x23F58: lea      r8, [rsp + 0x190]
0x23F60: mov      rdx, rdi
0x23F63: mov      rcx, r12
0x23F66: call     0x3c6f4
0x23F6B: mov      ecx, eax
0x23F6D: mov      dword ptr [rsp + 0x90], eax
0x23F74: cmp      eax, esi
0x23F76: jl       0x24173
0x23F7C: bt       dword ptr [r12], 0xb
0x23F82: jae      0x23f9d
0x23F84: mov      r9d, dword ptr [r13]
0x23F88: lea      r8, [rip + 0x19eb1]  ; → L"佉呃彌䥓彖塏䕓䥍›灵㸭祴数††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭祴数††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭慤整††簠⸥猪੼찀쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭慤整††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭楴敭††簠⸥猪੼찀쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍"
0x23F8F: mov      edx, 2
0x23F94: lea      ecx, [rdx + 0x4b]
0x23F97: call     qword ptr [rip - 0xedbd]  ; → DbgPrintEx
0x23F9D: mov      word ptr [rsp + 0x192], r14w
0x23FA6: mov      word ptr [rsp + 0x190], 0x88
0x23FB0: mov      dword ptr [rsp + 0x1b4], 0xc
0x23FBB: mov      qword ptr [rsp + 0x1c0], rsi
0x23FC3: lea      r13, [rbx + 0xc]
0x23FC7: mov      qword ptr [rsp + 0x1b8], r13
0x23FCF: mov      byte ptr [rsp + 0x210], 0xc0
0x23FD7: mov      byte ptr [rsp + 0x211], 4
0x23FDF: mov      word ptr [rsp + 0x212], si
0x23FE7: mov      word ptr [rsp + 0x214], si
0x23FEF: mov      dword ptr [rsp + 0x1b0], 1
0x23FFA: mov      qword ptr [rsp + 0x1c8], rsi
0x24002: lea      r8, [rsp + 0x190]
0x2400A: mov      rdx, rdi
0x2400D: mov      rcx, r12
0x24010: call     0x3c6f4
0x24015: mov      ecx, eax
0x24017: mov      dword ptr [rsp + 0x90], eax
0x2401E: cmp      eax, esi
0x24020: jl       0x24140
0x24026: bt       dword ptr [r12], 0xb
0x2402C: jae      0x2404d
0x2402E: mov      qword ptr [rsp + 0x20], r13
0x24033: mov      r9d, 0xc
0x24039: lea      r8, [rip + 0x19e60]  ; → L"佉呃彌䥓彖塏䕓䥍›灵㸭慤整††簠⸥猪੼찀쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭慤整††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭楴敭††簠⸥猪੼찀쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭楴敭††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†汷⁨瀥†⸥匪
쳌쳌쳌쳌쳌"
0x24040: lea      edx, [r9 - 0xa]
0x24044: lea      ecx, [rdx + 0x4b]
0x24047: call     qword ptr [rip - 0xee6d]  ; → DbgPrintEx
0x2404D: mov      word ptr [rsp + 0x192], r14w
0x24056: mov      word ptr [rsp + 0x190], 0x88
0x24060: mov      dword ptr [rsp + 0x1b4], 9
0x2406B: mov      qword ptr [rsp + 0x1c0], rsi
0x24073: add      rbx, 0x18
0x24077: mov      qword ptr [rsp + 0x1b8], rbx
0x2407F: mov      byte ptr [rsp + 0x210], 0xc0
0x24087: mov      byte ptr [rsp + 0x211], 3
0x2408F: mov      word ptr [rsp + 0x212], si
0x24097: mov      word ptr [rsp + 0x214], si
0x2409F: mov      dword ptr [rsp + 0x1b0], 1
0x240AA: mov      qword ptr [rsp + 0x1c8], rsi
0x240B2: lea      r8, [rsp + 0x190]
0x240BA: mov      rdx, rdi
0x240BD: mov      rcx, r12
0x240C0: call     0x3c6f4
0x240C5: mov      ecx, eax
0x240C7: mov      dword ptr [rsp + 0x90], eax
0x240CE: cmp      eax, esi
0x240D0: jl       0x2410d
0x240D2: bt       dword ptr [r12], 0xb
0x240D8: jae      0x240f9
0x240DA: mov      qword ptr [rsp + 0x20], rbx
0x240DF: mov      r9d, 9
0x240E5: lea      r8, [rip + 0x19e14]  ; → L"佉呃彌䥓彖塏䕓䥍›灵㸭楴敭††簠⸥猪੼찀쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭楴敭††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†汷⁨瀥†⸥匪
쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†睚畑牥卹浹潢楬䱣湩佫橢捥⡴┠⨮⁓ ‭〥堸猥
쳌쳌쳌쳌쳌쳌"
0x240EC: lea      edx, [r9 - 7]
0x240F0: lea      ecx, [rdx + 0x4b]
0x240F3: call     qword ptr [rip - 0xef19]  ; → DbgPrintEx
0x240F9: mov      qword ptr [r15 + 0x38], 0x24
0x24101: mov      dword ptr [rsp + 0x90], esi
0x24108: jmp      0x28e31
0x2410D: bt       dword ptr [r12], 0x1f
0x24113: jae      0x28e31
0x24119: call     0x12acc
0x2411E: mov      qword ptr [rsp + 0x20], rax
0x24123: mov      r9d, ecx
0x24126: lea      r8, [rip + 0x19e03]  ; → L"佉呃彌䥓彖塏䕓䥍›灵㸭楴敭††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†汷⁨瀥†⸥匪
쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†睚畑牥卹浹潢楬䱣湩佫橢捥⡴┠⨮⁓ ‭〥堸猥
쳌쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†睚灏湥祓"
0x2412D: mov      edx, 2
0x24132: lea      ecx, [rdx + 0x4b]
0x24135: call     qword ptr [rip - 0xef5b]  ; → DbgPrintEx
0x2413B: jmp      0x28e31
0x24140: bt       dword ptr [r12], 0x1f
0x24146: jae      0x28e31
0x2414C: call     0x12acc
0x24151: mov      qword ptr [rsp + 0x20], rax
0x24156: mov      r9d, ecx
0x24159: lea      r8, [rip + 0x19d70]  ; → L"佉呃彌䥓彖塏䕓䥍›灵㸭慤整††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭楴敭††簠⸥猪੼찀쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭楴敭††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†汷⁨瀥†⸥匪
쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†睚畑牥卹"
0x24160: mov      edx, 2
0x24165: lea      ecx, [rdx + 0x4b]
0x24168: call     qword ptr [rip - 0xef8e]  ; → DbgPrintEx
0x2416E: jmp      0x28e31
0x24173: bt       dword ptr [r12], 0x1f
0x24179: jae      0x28e31
0x2417F: call     0x12acc
0x24184: mov      qword ptr [rsp + 0x20], rax
0x24189: mov      r9d, ecx
0x2418C: lea      r8, [rip + 0x19cdd]  ; → L"佉呃彌䥓彖塏䕓䥍›灵㸭祴数††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭慤整††簠⸥猪੼찀쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭慤整††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭楴敭††簠⸥猪੼찀쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭楴敭††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖啑剅彙"
0x24193: mov      edx, 2
0x24198: lea      ecx, [rdx + 0x4b]
0x2419B: call     qword ptr [rip - 0xefc1]  ; → DbgPrintEx
0x241A1: jmp      0x28e31
0x241A6: bt       dword ptr [r12], 0x1f
0x241AC: jae      0x28e31
0x241B2: call     0x12acc
0x241B7: mov      qword ptr [rsp + 0x20], rax
0x241BC: mov      r9d, ecx
0x241BF: lea      r8, [rip + 0x19c4a]  ; → L"佉呃彌䥓彖塏䕓䥍›灵㸭䙶硩††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭祴数††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭祴数††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭慤整††簠⸥猪੼찀쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭慤整††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍"
0x241C6: mov      edx, 2
0x241CB: lea      ecx, [rdx + 0x4b]
0x241CE: call     qword ptr [rip - 0xeff4]  ; → DbgPrintEx
0x241D4: jmp      0x28e31
0x241D9: bt       dword ptr [r12], 0x1f
0x241DF: jae      0x28e31
0x241E5: call     0x12acc
0x241EA: mov      qword ptr [rsp + 0x20], rax
0x241EF: mov      r9d, ecx
0x241F2: lea      r8, [rip + 0x19bb7]  ; → L"佉呃彌䥓彖塏䕓䥍›灵㸭䑶癥††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭䙶硩††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭䙶硩††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭祴数††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭祴数††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍"
0x241F9: mov      edx, 2
0x241FE: lea      ecx, [rdx + 0x4b]
0x24201: call     qword ptr [rip - 0xf027]  ; → DbgPrintEx
0x24207: jmp      0x28e31
0x2420C: cmp      r13d, 0xf58
0x24213: jb       0x243b0
0x24219: cmp      ebx, 0x28
0x2421C: jb       0x243b0
0x24222: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x2422D: movzx    eax, word ptr [r14 + 0x20]
0x24232: cmp      ax, si
0x24235: je       0x24276
0x24237: cmp      ax, word ptr [r12 + 0x294]
0x24240: jne      0x24254
0x24242: lea      rbx, [r12 + 0x258]
0x2424A: mov      qword ptr [rsp + 0x120], rbx
0x24252: jmp      0x24286
0x24254: cmp      ax, word ptr [r12 + 0x41c]
0x2425D: jne      0x24271
0x2425F: lea      rbx, [r12 + 0x3e0]
0x24267: mov      qword ptr [rsp + 0x120], rbx
0x2426F: jmp      0x24286
0x24271: jmp      0x28e31
0x24276: lea      rbx, [r12 + 0x258]
0x2427E: mov      qword ptr [rsp + 0x120], rbx
0x24286: mov      rcx, r14
0x24289: call     0x3a0e0
0x2428E: cmp      qword ptr [rbx + 8], rsi
0x24292: je       0x242e4
0x24294: mov      eax, dword ptr [rbx + 0x34]
0x24297: mov      dword ptr [r14 + 4], eax
0x2429B: movzx    eax, word ptr [rbx + 0x38]
0x2429F: mov      word ptr [r14 + 0x1c], ax
0x242A4: movzx    eax, word ptr [rbx + 0x3a]
0x242A8: mov      word ptr [r14 + 0x1e], ax
0x242AD: mov      eax, dword ptr [rbx + 0x4c]
0x242B0: mov      dword ptr [r14 + 8], eax
0x242B4: mov      eax, dword ptr [rbx + 0x50]
0x242B7: mov      dword ptr [r14 + 0xc], eax
0x242BB: movzx    eax, word ptr [rbx + 0x40]
0x242BF: mov      word ptr [r14 + 0x22], ax
0x242C4: movzx    eax, word ptr [rbx + 0x42]
0x242C8: mov      word ptr [r14 + 0x24], ax
0x242CD: movzx    eax, word ptr [rbx + 0x44]
0x242D1: mov      word ptr [r14 + 0x26], ax
0x242D6: mov      r8, r14
0x242D9: mov      rdx, rbx
0x242DC: mov      rcx, r12
0x242DF: call     qword ptr [rbx + 8]
0x242E2: jmp      0x24301
0x242E4: movzx    eax, word ptr [rbx + 0x44]
0x242E8: mov      word ptr [rsp + 0x20], ax
0x242ED: movzx    r9d, word ptr [rbx + 0x42]
0x242F2: mov      r8d, dword ptr [rbx + 0x34]
0x242F6: mov      rdx, r14
0x242F9: mov      rcx, r12
0x242FC: call     0x3ba9c
0x24301: cmp      qword ptr [rbx + 0x20], rsi
0x24305: je       0x24313
0x24307: mov      r8, r14
0x2430A: mov      rdx, rbx
0x2430D: mov      rcx, r12
0x24310: call     qword ptr [rbx + 0x20]
0x24313: movzx    eax, word ptr [rbx + 0x3c]
0x24317: mov      word ptr [r14 + 0x20], ax
0x2431C: mov      eax, dword ptr [rbx + 0x30]
0x2431F: mov      dword ptr [r14], eax
0x24322: movzx    eax, word ptr [rbx + 0x82]
0x24329: cmp      word ptr [r14 + 0x14], ax
0x2432E: jae      0x24337
0x24330: movzx    eax, word ptr [r14 + 0x14]
0x24335: jmp      0x2433a
0x24337: movzx    eax, ax
0x2433A: mov      word ptr [r14 + 0x14], ax
0x2433F: movzx    r8d, ax
0x24343: lea      rdx, [rbx + 0x84]
0x2434A: lea      rcx, [r14 + 0x256]
0x24351: call     0x12e10
0x24356: movzx    edx, word ptr [r14 + 0x16]
0x2435B: mov      dword ptr [rsp + 0x94], edx
0x24362: cmp      edx, esi
0x24364: je       0x24376
0x24366: lea      rax, [rdx + 0x356]
0x2436D: mov      dword ptr [rsp + 0x94], eax
0x24374: jmp      0x24388
0x24376: movzx    eax, word ptr [r14 + 0x14]
0x2437B: add      rax, 0x256
0x24381: mov      dword ptr [rsp + 0x94], eax
0x24388: mov      eax, eax
0x2438A: mov      qword ptr [r15 + 0x38], rax
0x2438E: mov      dword ptr [rsp + 0x90], esi
0x24395: jmp      0x243b0
0x24397: mov      dword ptr [rsp + 0x90], eax
0x2439E: xor      esi, esi
0x243A0: mov      r12, qword ptr [rsp + 0xe0]
0x243A8: mov      r15, qword ptr [rsp + 0xe8]
0x243B0: jmp      0x28e31
0x243B5: test     bl, 3
0x243B8: jne      0x28e31
0x243BE: test     r13b, 3
0x243C2: jne      0x28e31
0x243C8: cmp      ebx, 0xc  ← IOCTL 0x0C (WRMSR)
0x243CB: jb       0x28e31
0x243D1: lea      rcx, [rbx - 8]
0x243D5: mov      eax, r13d
0x243D8: cmp      rax, rcx
0x243DB: jb       0x28e31
0x243E1: mov      dword ptr [rsp + 0x90], 0xc000000e
0x243EC: cmp      dword ptr [r12 + 0x1dc], esi
0x243F4: je       0x28e31
0x243FA: mov      r13d, dword ptr [r14]
0x243FD: mov      dword ptr [rsp + 0xd8], r13d
0x24405: mov      eax, dword ptr [r14 + 4]
0x24409: add      ebx, -8
0x2440C: mov      dword ptr [rsp + 0x94], ebx
0x24413: cmp      r13d, 0xff
0x2441A: ja       0x28e31
0x24420: add      rbx, r14
0x24423: cmp      r14, rbx
0x24426: jae      0x2448d
0x24428: mov      r15d, eax
0x2442B: lea      r9, [rdi + 8]
0x2442F: mov      dword ptr [rsp + 0x28], 4
0x24437: mov      dword ptr [rsp + 0x20], 0xe0
0x2443F: mov      r8d, r15d
0x24442: mov      edx, r13d
0x24445: mov      rcx, r12
0x24448: call     0x11ae4
0x2444D: cmp      eax, 4
0x24450: jne      0x24485
0x24452: mov      dword ptr [rsp + 0x28], eax
0x24456: mov      dword ptr [rsp + 0x20], 0xe4
0x2445E: mov      r9, rdi
0x24461: mov      r8d, r15d
0x24464: mov      edx, r13d
0x24467: mov      rcx, r12
0x2446A: call     0x119c8
0x2446F: cmp      eax, 4
0x24472: jne      0x24485
0x24474: add      rdi, 4
0x24478: mov      qword ptr [rsp + 0x138], rdi
0x24480: cmp      rdi, rbx
0x24483: jb       0x2442b
0x24485: mov      r15, qword ptr [rsp + 0x120]
0x2448D: sub      edi, r14d
0x24490: mov      eax, edi
0x24492: mov      qword ptr [r15 + 0x38], rax
0x24496: mov      dword ptr [rsp + 0x90], esi
0x2449D: jmp      0x28e31
0x244A2: test     bl, 3
0x244A5: jne      0x28e31
0x244AB: cmp      ebx, 0x38
0x244AE: jb       0x28e31
0x244B4: test     r13b, 3
0x244B8: jne      0x28e31
0x244BE: cmp      r13d, 0x38
0x244C2: jb       0x28e31
0x244C8: mov      dword ptr [rsp + 0x90], 0xc000000e
0x244D3: cmp      qword ptr [r12 + 0x1e0], rsi
0x244DB: je       0x28e31
0x244E1: cmp      qword ptr [r12 + 0x1e8], rsi
0x244E9: je       0x28e31
0x244EF: lea      r9, [r15 + 0x30]
0x244F3: mov      r8d, r13d
0x244F6: mov      rdx, r14
0x244F9: mov      rcx, r12
0x244FC: call     0x2b180
0x24501: mov      dword ptr [rsp + 0x90], eax
0x24508: jmp      0x28e31
0x2450D: cmp      ebx, 4
0x24510: jne      0x24536
0x24512: cmp      r13d, esi
0x24515: jne      0x24536
0x24517: movzx    eax, word ptr [rcx]
0x2451A: mov      word ptr [r12 + 0x2c], ax
0x24520: movzx    eax, word ptr [rcx + 2]
0x24524: mov      word ptr [r12 + 0x2e], ax
0x2452A: mov      dword ptr [rsp + 0x90], esi
0x24531: jmp      0x28e31
0x24536: cmp      ebx, 2
0x24539: jb       0x28e31
0x2453F: cmp      r13d, 0x46
0x24543: jb       0x28e31
0x24549: lea      rax, [r15 + 0x30]
0x2454D: mov      qword ptr [rsp + 0x20], rax
0x24552: mov      r9d, r13d
0x24555: mov      r8d, ebx
0x24558: mov      rdx, r14
0x2455B: mov      rcx, r12
0x2455E: call     0x2b938
0x24563: mov      dword ptr [rsp + 0x90], eax
0x2456A: jmp      0x28e31
0x2456F: mov      eax, edx
0x24571: sub      eax, 0x94
0x24576: je       0x248d6
0x2457C: sub      eax, 4
0x2457F: je       0x2480d
0x24585: sub      eax, 4
0x24588: je       0x24755
0x2458E: sub      eax, 4
0x24591: je       0x246cd
0x24597: sub      eax, 4
0x2459A: je       0x24639
0x245A0: cmp      eax, 4
0x245A3: jne      0x28372
0x245A9: and      r13d, 0xfffffffc
0x245AD: mov      dword ptr [rsp + 0x94], r13d
0x245B5: cmp      ebx, 2
0x245B8: jb       0x24634
0x245BA: cmp      r13d, eax
0x245BD: jb       0x24634
0x245BF: movzx    edx, word ptr [rcx]
0x245C2: mov      word ptr [rsp + 0xc8], dx
0x245CA: add      r13d, edx
0x245CD: mov      dword ptr [rsp + 0x94], r13d
0x245D5: movzx    eax, dx
0x245D8: cmp      eax, r13d
0x245DB: jae      0x2460a
0x245DD: in       eax, dx
0x245DE: mov      dword ptr [rdi], eax
0x245E0: add      rdi, 4
0x245E4: mov      qword ptr [rsp + 0x138], rdi
0x245EC: mov      dx, word ptr [rsp + 0xc8]
0x245F4: add      rdx, 4
0x245F8: mov      word ptr [rsp + 0xc8], dx
0x24600: mov      r13d, dword ptr [rsp + 0x94]
0x24608: jmp      0x245d5
0x2460A: sub      edi, ecx
0x2460C: mov      eax, edi
0x2460E: mov      qword ptr [r15 + 0x38], rax
0x24612: mov      dword ptr [rsp + 0x90], esi
0x24619: jmp      0x24634
0x2461B: mov      dword ptr [rsp + 0x90], eax
0x24622: xor      esi, esi
0x24624: mov      r12, qword ptr [rsp + 0xe0]
0x2462C: mov      r15, qword ptr [rsp + 0xe8]
0x24634: jmp      0x28e31
0x24639: and      r13d, 0xfffffffe
0x2463D: mov      dword ptr [rsp + 0x94], r13d
0x24645: cmp      ebx, 2
0x24648: jb       0x246c8
0x2464A: cmp      r13d, 2
0x2464E: jb       0x246c8
0x24650: movzx    edx, word ptr [rcx]
0x24653: mov      word ptr [rsp + 0xc8], dx
0x2465B: add      r13d, edx
0x2465E: mov      dword ptr [rsp + 0x94], r13d
0x24666: movzx    eax, dx
0x24669: cmp      eax, r13d
0x2466C: jae      0x2469d
0x2466E: in       ax, dx
0x24670: mov      word ptr [rcx], ax
0x24673: add      rcx, 2
0x24677: mov      qword ptr [rsp + 0x230], rcx
0x2467F: mov      dx, word ptr [rsp + 0xc8]
0x24687: add      rdx, 2
0x2468B: mov      word ptr [rsp + 0xc8], dx
0x24693: mov      r13d, dword ptr [rsp + 0x94]
0x2469B: jmp      0x24666
0x2469D: sub      ecx, r14d
0x246A0: mov      eax, ecx
0x246A2: mov      qword ptr [r15 + 0x38], rax
0x246A6: mov      dword ptr [rsp + 0x90], esi
0x246AD: jmp      0x246c8
0x246AF: mov      dword ptr [rsp + 0x90], eax
0x246B6: xor      esi, esi
0x246B8: mov      r12, qword ptr [rsp + 0xe0]
0x246C0: mov      r15, qword ptr [rsp + 0xe8]
0x246C8: jmp      0x28e31
0x246CD: cmp      ebx, 2
0x246D0: jb       0x24750
0x246D2: cmp      r13d, 1
0x246D6: jb       0x24750
0x246D8: movzx    edx, word ptr [rcx]
0x246DB: mov      word ptr [rsp + 0xc8], dx
0x246E3: add      r13d, edx
0x246E6: mov      dword ptr [rsp + 0x94], r13d
0x246EE: movzx    eax, dx
0x246F1: cmp      eax, r13d
0x246F4: jae      0x24724
0x246F6: in       al, dx
0x246F7: mov      byte ptr [r14], al
0x246FA: add      r14, 1
0x246FE: mov      qword ptr [rsp + 0x148], r14
0x24706: mov      dx, word ptr [rsp + 0xc8]
0x2470E: add      rdx, 1
0x24712: mov      word ptr [rsp + 0xc8], dx
0x2471A: mov      r13d, dword ptr [rsp + 0x94]
0x24722: jmp      0x246ee
0x24724: sub      r14d, edi
0x24727: mov      eax, r14d
0x2472A: mov      qword ptr [r15 + 0x38], rax
0x2472E: mov      dword ptr [rsp + 0x90], esi
0x24735: jmp      0x24750
0x24737: mov      dword ptr [rsp + 0x90], eax
0x2473E: xor      esi, esi
0x24740: mov      r12, qword ptr [rsp + 0xe0]
0x24748: mov      r15, qword ptr [rsp + 0xe8]
0x24750: jmp      0x28e31
0x24755: cmp      r13d, 0x110
0x2475C: jb       0x28e31
0x24762: cmp      ebx, r8d
0x24765: jb       0x28e31
0x2476B: lea      rbx, [r12 + 0x258]
0x24773: mov      qword ptr [rsp + 0x120], rbx
0x2477B: cmp      byte ptr [r14], sil
0x2477E: je       0x24796
0x24780: lea      rbx, [r12 + 0x3e0]
0x24788: mov      qword ptr [rsp + 0x120], rbx
0x24790: cmp      byte ptr [r14], 1
0x24794: jne      0x247fd
0x24796: movzx    eax, word ptr [rbx + 0x38]
0x2479A: cmp      word ptr [r14 + 8], ax
0x2479F: jne      0x247fd
0x247A1: movzx    eax, word ptr [rbx + 0x3a]
0x247A5: cmp      word ptr [r14 + 0xa], ax
0x247AA: jne      0x247fd
0x247AC: mov      eax, dword ptr [rbx + 0x34]
0x247AF: cmp      dword ptr [r14 + 4], eax
0x247B3: jne      0x247fd
0x247B5: movzx    eax, word ptr [rbx + 0x3c]
0x247B9: cmp      word ptr [r14 + 2], ax
0x247BE: jne      0x247fd
0x247C0: cmp      qword ptr [rbx + 0x18], rsi
0x247C4: je       0x247fd
0x247C6: movzx    eax, byte ptr [r14 + 0xf]
0x247CB: movzx    r9d, byte ptr [r14 + 0xe]
0x247D0: mov      dword ptr [rsp + 0x20], eax
0x247D4: mov      r8, r14
0x247D7: mov      rdx, rbx
0x247DA: mov      rcx, r12
0x247DD: call     qword ptr [rbx + 0x18]
0x247E0: mov      dword ptr [rsp + 0x94], eax
0x247E7: mov      ecx, eax
0x247E9: add      rcx, 0x10
0x247ED: mov      qword ptr [r15 + 0x38], rcx
0x247F1: mov      dword ptr [rsp + 0x90], esi
0x247F8: jmp      0x28e31
0x247FD: mov      dword ptr [rsp + 0x90], 0xc0000225
0x24808: jmp      0x28e31
0x2480D: cmp      r13d, 0x110
0x24814: jb       0x28e31
0x2481A: cmp      ebx, r8d
0x2481D: jb       0x28e31
0x24823: lea      rbx, [r12 + 0x258]
0x2482B: mov      qword ptr [rsp + 0x120], rbx
0x24833: cmp      byte ptr [r14], sil
0x24836: je       0x2484e
0x24838: lea      rbx, [r12 + 0x3e0]
0x24840: mov      qword ptr [rsp + 0x120], rbx
0x24848: cmp      byte ptr [r14], 1
0x2484C: jne      0x248c6
0x2484E: cmp      qword ptr [rbx + 0x10], rsi
0x24852: je       0x248c6
0x24854: movzx    eax, word ptr [rbx + 0x38]
0x24858: mov      word ptr [r14 + 8], ax
0x2485D: movzx    eax, word ptr [rbx + 0x3a]
0x24861: mov      word ptr [r14 + 0xa], ax
0x24866: mov      eax, dword ptr [rbx + 0x34]
0x24869: mov      dword ptr [r14 + 4], eax
0x2486D: movzx    eax, word ptr [rbx + 0x3c]
0x24871: mov      word ptr [r14 + 2], ax
0x24876: mov      al, byte ptr [rbx + 0x46]
0x24879: mov      byte ptr [r14 + 0xc], al
0x2487D: mov      byte ptr [r14 + 0xd], sil
0x24881: mov      al, byte ptr [r14 + 0xf]
0x24885: cmp      al, sil
0x24888: je       0x2488f
0x2488A: movzx    eax, al
0x2488D: jmp      0x24894
0x2488F: mov      eax, 0x100
0x24894: movzx    r9d, byte ptr [r14 + 0xe]
0x24899: mov      dword ptr [rsp + 0x20], eax
0x2489D: mov      r8, r14
0x248A0: mov      rdx, rbx
0x248A3: mov      rcx, r12
0x248A6: call     qword ptr [rbx + 0x10]
0x248A9: mov      dword ptr [rsp + 0x94], eax
0x248B0: mov      ecx, eax
0x248B2: add      rcx, 0x10
0x248B6: mov      qword ptr [r15 + 0x38], rcx
0x248BA: mov      dword ptr [rsp + 0x90], esi
0x248C1: jmp      0x28e31
0x248C6: mov      dword ptr [rsp + 0x90], 0xc0000225
0x248D1: jmp      0x28e31
0x248D6: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x248E1: jmp      0x28e31
0x248E6: cmp      ebx, 3
0x248E9: jb       0x24919
0x248EB: movzx    edx, word ptr [rcx]
0x248EE: mov      al, byte ptr [r14 + 2]
0x248F2: out      dx, al
0x248F3: mov      qword ptr [r15 + 0x38], rsi
0x248F7: mov      dword ptr [rsp + 0x90], esi
0x248FE: jmp      0x24919
0x24900: mov      dword ptr [rsp + 0x90], eax
0x24907: xor      esi, esi
0x24909: mov      r12, qword ptr [rsp + 0xe0]
0x24911: mov      r15, qword ptr [rsp + 0xe8]
0x24919: jmp      0x28e31
0x2491E: mov      eax, 0xd8
0x24923: cmp      edx, eax
0x24925: ja       0x253c9
0x2492B: cmp      edx, eax
0x2492D: je       0x253a7
0x24933: mov      eax, edx
0x24935: sub      eax, 0xb4
0x2493A: je       0x2536e
0x24940: sub      eax, 4
0x24943: je       0x25336
0x24949: sub      eax, 8
0x2494C: je       0x2510d
0x24952: sub      eax, 4
0x24955: je       0x24c58
0x2495B: sub      eax, 4
0x2495E: je       0x24a1e
0x24964: cmp      eax, 8  ← IOCTL 0x08 (RDMSR)
0x24967: jne      0x28372
0x2496D: cmp      ebx, 0x38
0x24970: jb       0x28e31
0x24976: cmp      r13d, 0x38
0x2497A: jb       0x28e31
0x24980: mov      rbx, qword ptr [r15 + 0x18]
0x24984: mov      rdx, qword ptr [rbx]
0x24987: mov      qword ptr [rsp + 0xb8], rdx
0x2498F: cmp      rdx, rsi
0x24992: je       0x249d2
0x24994: mov      edi, 0x400
0x24999: lea      r9d, [rax - 7]
0x2499D: mov      r8, rdi
0x249A0: mov      rcx, r12
0x249A3: call     0x29a50
0x249A8: mov      rdx, rax
0x249AB: mov      qword ptr [rsp + 0x100], rax
0x249B3: cmp      rax, rsi
0x249B6: je       0x249d2
0x249B8: mov      eax, dword ptr [rax + 4]
0x249BB: mov      dword ptr [rbx + 8], eax
0x249BE: mov      eax, dword ptr [rdx + 0xf0]
0x249C4: mov      dword ptr [rbx + 0xc], eax
0x249C7: mov      r8, rdi
0x249CA: mov      rcx, r12
0x249CD: call     0x29c2c
0x249D2: mov      eax, dword ptr [rbx + 0x10]
0x249D5: mov      dword ptr [rsp + 0x98], eax
0x249DC: cmp      eax, esi
0x249DE: je       0x249e9
0x249E0: movzx    edx, ax
0x249E3: in       eax, dx
0x249E4: mov      dword ptr [rbx + 0x14], eax
0x249E7: jmp      0x249ec
0x249E9: mov      dword ptr [rbx + 0x14], esi
0x249EC: xor      ecx, ecx
0x249EE: call     qword ptr [r12 + 0x110]
0x249F6: mov      qword ptr [rbx + 0x28], rax
0x249FA: mov      eax, dword ptr [r12 + 0x4c]
0x249FF: mov      dword ptr [rbx + 0x30], eax
0x24A02: mov      eax, dword ptr [r12 + 0x50]
0x24A07: mov      dword ptr [rbx + 0x34], eax
0x24A0A: mov      qword ptr [r15 + 0x38], 0x38
0x24A12: mov      dword ptr [rsp + 0x90], esi
0x24A19: jmp      0x28e31
0x24A1E: mov      qword ptr [rsp + 0x118], rcx
0x24A26: mov      word ptr [rsp + 0x110], bx
0x24A2E: mov      word ptr [rsp + 0x112], bx
0x24A36: lea      r9, [rsp + 0xa8]
0x24A3E: lea      r8, [rsp + 0x180]
0x24A46: mov      edx, 0x120089
0x24A4B: lea      rcx, [rsp + 0x110]
0x24A53: call     qword ptr [rip - 0xf941]  ; → IoGetDeviceObjectPointer
0x24A59: mov      edx, eax
0x24A5B: mov      dword ptr [rsp + 0x90], eax
0x24A62: cmp      eax, esi
0x24A64: jge      0x24ace
0x24A66: bt       dword ptr [r12], 0x1f
0x24A6C: jae      0x28e31
0x24A72: mov      ecx, eax
0x24A74: call     0x12acc
0x24A79: movzx    ecx, word ptr [rsp + 0x110]
0x24A81: shr      rcx, 1
0x24A84: mov      qword ptr [rsp + 0x40], rax
0x24A89: mov      dword ptr [rsp + 0x38], edx
0x24A8D: mov      rax, qword ptr [rsp + 0x118]
0x24A95: mov      qword ptr [rsp + 0x30], rax
0x24A9A: mov      qword ptr [rsp + 0x28], rcx
0x24A9F: mov      rdi, qword ptr [rsp + 0xc0]
0x24AA7: mov      qword ptr [rsp + 0x20], rdi
0x24AAC: mov      r9, qword ptr [rsp + 0xb8]
0x24AB4: lea      r8, [rip + 0x19735]  ; → L"佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†摢⁯瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†摡⁯瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䍁䥐䡟䅅⁄
쳌쳌쳌쳌쳌"
0x24ABB: mov      edx, 2
0x24AC0: lea      ecx, [rdx + 0x4b]
0x24AC3: call     qword ptr [rip - 0xf8e9]  ; → DbgPrintEx
0x24AC9: jmp      0x28e31
0x24ACE: mov      rcx, qword ptr [rsp + 0xa8]
0x24AD6: call     qword ptr [rip - 0xf95c]  ; → ObfReferenceObject
0x24ADC: mov      rcx, qword ptr [rsp + 0x180]
0x24AE4: call     qword ptr [rip - 0xf95a]  ; → ObfDereferenceObject
0x24AEA: lea      rdx, [rsp + 0x108]
0x24AF2: mov      rcx, qword ptr [rsp + 0xa8]
0x24AFA: call     qword ptr [r12 + 0x168]
0x24B02: mov      edx, eax
0x24B04: mov      dword ptr [rsp + 0x90], eax
0x24B0B: cmp      eax, esi
0x24B0D: jl       0x24bd9
0x24B13: lea      rax, [rsp + 0x98]
0x24B1B: mov      qword ptr [rsp + 0x20], rax
0x24B20: mov      r9, qword ptr [rsp + 0xd0]
0x24B28: mov      r8d, dword ptr [rsp + 0x94]
0x24B30: mov      edx, 0xb
0x24B35: mov      rcx, qword ptr [rsp + 0x108]
0x24B3D: call     qword ptr [rip - 0xf96b]  ; → IoGetDeviceProperty
0x24B43: mov      edx, eax
0x24B45: mov      dword ptr [rsp + 0x90], eax
0x24B4C: cmp      eax, esi
0x24B4E: jl       0x24b5d
0x24B50: mov      eax, dword ptr [rsp + 0x98]
0x24B57: mov      qword ptr [r15 + 0x38], rax
0x24B5B: jmp      0x24bc9
0x24B5D: bt       dword ptr [r12], 0x1f
0x24B63: jae      0x24bc9
0x24B65: mov      ecx, eax
0x24B67: call     0x12acc
0x24B6C: movzx    ecx, word ptr [rsp + 0x110]
0x24B74: shr      rcx, 1
0x24B77: mov      qword ptr [rsp + 0x48], rax
0x24B7C: mov      dword ptr [rsp + 0x40], edx
0x24B80: mov      rax, qword ptr [rsp + 0x118]
0x24B88: mov      qword ptr [rsp + 0x38], rax
0x24B8D: mov      qword ptr [rsp + 0x30], rcx
0x24B92: mov      rax, qword ptr [rsp + 0x108]
0x24B9A: mov      qword ptr [rsp + 0x28], rax
0x24B9F: mov      rdi, qword ptr [rsp + 0xc0]
0x24BA7: mov      qword ptr [rsp + 0x20], rdi
0x24BAC: mov      r9, qword ptr [rsp + 0xb8]
0x24BB4: lea      r8, [rip + 0x19675]  ; → L"佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†摢⁯瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†摡⁯瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䍁䥐䡟䅅⁄
쳌쳌쳌쳌쳌䕇彔剐䍏卅体归䉏彊义但찀쳌쳌쳌쳌䍁䥐䕟啎彍䡃䱉剄久┠㈰⁘┠⁵┠╣"
0x24BBB: mov      edx, 2
0x24BC0: lea      ecx, [rdx + 0x4b]
0x24BC3: call     qword ptr [rip - 0xf9e9]  ; → DbgPrintEx
0x24BC9: mov      rcx, qword ptr [rsp + 0x108]
0x24BD1: call     qword ptr [rip - 0xfa47]  ; → ObfDereferenceObject
0x24BD7: jmp      0x24c45
0x24BD9: bt       dword ptr [r12], 0x1f
0x24BDF: jae      0x24c45
0x24BE1: mov      ecx, eax
0x24BE3: call     0x12acc
0x24BE8: movzx    ecx, word ptr [rsp + 0x110]
0x24BF0: shr      rcx, 1
0x24BF3: mov      qword ptr [rsp + 0x48], rax
0x24BF8: mov      dword ptr [rsp + 0x40], edx
0x24BFC: mov      rax, qword ptr [rsp + 0x118]
0x24C04: mov      qword ptr [rsp + 0x38], rax
0x24C09: mov      qword ptr [rsp + 0x30], rcx
0x24C0E: mov      rax, qword ptr [rsp + 0xa8]
0x24C16: mov      qword ptr [rsp + 0x28], rax
0x24C1B: mov      rdi, qword ptr [rsp + 0xc0]
0x24C23: mov      qword ptr [rsp + 0x20], rdi
0x24C28: mov      r9, qword ptr [rsp + 0xb8]
0x24C30: lea      r8, [rip + 0x19649]  ; → L"佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†摡⁯瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䍁䥐䡟䅅⁄
쳌쳌쳌쳌쳌䕇彔剐䍏卅体归䉏彊义但찀쳌쳌쳌쳌䍁䥐䕟啎彍䡃䱉剄久┠㈰⁘┠⁵┠╣╣╣⁣漠潦┠⁰漠硦┠⁰┠⁳瀥†灩┠⁰ⴥ甲†灯┠⁰甥
쳌쳌쳌쳌쳌쳌䍁䥐䕟啎彍䡃䱉剄"
0x24C37: mov      edx, 2
0x24C3C: lea      ecx, [rdx + 0x4b]
0x24C3F: call     qword ptr [rip - 0xfa65]  ; → DbgPrintEx
0x24C45: mov      rcx, qword ptr [rsp + 0xa8]
0x24C4D: call     qword ptr [rip - 0xfac3]  ; → ObfDereferenceObject
0x24C53: jmp      0x28e31
0x24C58: mov      eax, esi
0x24C5A: mov      dword ptr [rsp + 0x9c], eax
0x24C61: mov      r13d, 0x40
0x24C67: mov      rdi, qword ptr [rsp + 0xc0]
0x24C6F: mov      dword ptr [rsp + 0x30], eax
0x24C73: lea      rax, [rip + 0x193e6]  ; → L"\Device\Harddisk%u\Partition0"
0x24C7A: mov      qword ptr [rsp + 0x28], rax
0x24C7F: mov      dword ptr [rsp + 0x20], 0x800
0x24C87: xor      r9d, r9d
0x24C8A: lea      r8, [rsp + 0x128]
0x24C92: mov      edx, 0x100
0x24C97: lea      rcx, [rsp + 0x310]
0x24C9F: call     0x11008
0x24CA4: lea      r11, [rsp + 0x310]
0x24CAC: mov      qword ptr [rsp + 0x118], r11
0x24CB4: lea      rax, [rsp + 0x310]
0x24CBC: mov      r14, qword ptr [rsp + 0x128]
0x24CC4: sub      r14, rax
0x24CC7: sar      r14, 1
0x24CCA: mov      qword ptr [rsp + 0x150], r14
0x24CD2: movzx    eax, r14w
0x24CD6: add      ax, ax
0x24CD9: mov      word ptr [rsp + 0x112], ax
0x24CE1: mov      word ptr [rsp + 0x110], ax
0x24CE9: mov      dword ptr [rsp + 0x240], 0x30
0x24CF4: mov      qword ptr [rsp + 0x248], rsi
0x24CFC: mov      dword ptr [rsp + 0x258], r13d
0x24D04: lea      rax, [rsp + 0x110]
0x24D0C: mov      qword ptr [rsp + 0x250], rax
0x24D14: mov      qword ptr [rsp + 0x260], rsi
0x24D1C: mov      qword ptr [rsp + 0x268], rsi
0x24D24: lea      r8, [rsp + 0x240]
0x24D2C: mov      edx, 0x80000000
0x24D31: lea      rcx, [rsp + 0x140]
0x24D39: call     qword ptr [rip - 0xfc67]  ; → ZwOpenSymbolicLinkObject
0x24D3F: mov      ecx, eax
0x24D41: mov      dword ptr [rsp + 0x90], eax
0x24D48: cmp      eax, esi
0x24D4A: jl       0x25040
0x24D50: lea      rax, [rsp + 0x310]
0x24D58: mov      qword ptr [rsp + 0x118], rax
0x24D60: mov      word ptr [rsp + 0x112], 0x200
0x24D6A: mov      word ptr [rsp + 0x110], 0x200
0x24D74: lea      r8, [rsp + 0x98]
0x24D7C: lea      rdx, [rsp + 0x110]
0x24D84: mov      rcx, qword ptr [rsp + 0x140]
0x24D8C: call     qword ptr [rip - 0xfd32]  ; → ZwQuerySymbolicLinkObject
0x24D92: mov      r14d, eax
0x24D95: mov      dword ptr [rsp + 0x90], eax
0x24D9C: cmp      eax, esi
0x24D9E: jl       0x24db2
0x24DA0: movzx    eax, word ptr [rsp + 0x110]
0x24DA8: add      eax, 2
0x24DAB: mov      dword ptr [rsp + 0x98], eax
0x24DB2: mov      rcx, qword ptr [rsp + 0x140]
0x24DBA: call     qword ptr [rip - 0xfc88]  ; → ZwClose
0x24DC0: cmp      r14d, esi
0x24DC3: jl       0x24fe4
0x24DC9: movzx    eax, word ptr [rsp + 0x98]
0x24DD1: sub      ax, 2
0x24DD5: mov      word ptr [rsp + 0x110], ax
0x24DDD: lea      r9, [rsp + 0xa8]
0x24DE5: lea      r8, [rsp + 0x180]
0x24DED: mov      edx, 0x1f01ff
0x24DF2: lea      rcx, [rsp + 0x110]
0x24DFA: call     qword ptr [rip - 0xfce8]  ; → IoGetDeviceObjectPointer
0x24E00: mov      dword ptr [rsp + 0x90], eax
0x24E07: cmp      eax, esi
0x24E09: jl       0x25098
0x24E0F: bt       dword ptr [r12], 0xb
0x24E15: jae      0x24e68
0x24E17: movzx    eax, word ptr [rsp + 0x110]
0x24E1F: shr      rax, 1
0x24E22: lea      rcx, [rsp + 0x310]
0x24E2A: mov      qword ptr [rsp + 0x38], rcx
0x24E2F: mov      qword ptr [rsp + 0x30], rax
0x24E34: mov      rax, qword ptr [rsp + 0xa8]
0x24E3C: mov      qword ptr [rsp + 0x28], rax
0x24E41: mov      qword ptr [rsp + 0x20], rdi
0x24E46: mov      r14, qword ptr [rsp + 0xb8]
0x24E4E: mov      r9, r14
0x24E51: lea      r8, [rip + 0x19248]  ; → L"佉呃彌䥓彖啑剅彙䥄䭓††景⁯瀥†景⁸瀥†摡⁯瀥†⸥匪
쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥄䭓††景⁯瀥†景⁸瀥†摢⁯瀥†⸥匪
쳌쳌쳌쳌쳌\Device\Harddisk%u"
0x24E58: mov      edx, 2
0x24E5D: lea      ecx, [rdx + 0x4b]
0x24E60: call     qword ptr [rip - 0xfc86]  ; → DbgPrintEx
0x24E66: jmp      0x24e70
0x24E68: mov      r14, qword ptr [rsp + 0xb8]
0x24E70: mov      rdx, qword ptr [rsp + 0xa8]
0x24E78: mov      rcx, r12
0x24E7B: call     0x28fa0
0x24E80: mov      qword ptr [rsp + 0x108], rax
0x24E88: mov      rcx, qword ptr [rsp + 0x180]
0x24E90: call     qword ptr [rip - 0xfd06]  ; → ObfDereferenceObject
0x24E96: mov      rcx, qword ptr [rsp + 0x108]
0x24E9E: cmp      rcx, rsi
0x24EA1: je       0x25098
0x24EA7: lea      rax, [rsp + 0x98]
0x24EAF: mov      qword ptr [rsp + 0x20], rax
0x24EB4: lea      r9, [rsp + 0x310]
0x24EBC: mov      edx, 0xb
0x24EC1: mov      r8d, 0x200
0x24EC7: call     qword ptr [rip - 0xfcf5]  ; → IoGetDeviceProperty
0x24ECD: mov      dword ptr [rsp + 0x90], eax
0x24ED4: mov      rcx, qword ptr [rsp + 0x108]
0x24EDC: call     qword ptr [rip - 0xfd52]  ; → ObfDereferenceObject
0x24EE2: mov      ecx, dword ptr [rsp + 0x90]
0x24EE9: cmp      ecx, esi
0x24EEB: jl       0x24f8c
0x24EF1: mov      eax, dword ptr [rsp + 0x98]
0x24EF8: add      eax, -2
0x24EFB: mov      dword ptr [rsp + 0x98], eax
0x24F02: bt       dword ptr [r12], 0xb
0x24F08: jae      0x24f50
0x24F0A: shr      rax, 1
0x24F0D: lea      rcx, [rsp + 0x310]
0x24F15: mov      qword ptr [rsp + 0x38], rcx
0x24F1A: mov      qword ptr [rsp + 0x30], rax
0x24F1F: mov      rax, qword ptr [rsp + 0x108]
0x24F27: mov      qword ptr [rsp + 0x28], rax
0x24F2C: mov      qword ptr [rsp + 0x20], rdi
0x24F31: mov      r9, r14
0x24F34: lea      r8, [rip + 0x191a5]  ; → L"佉呃彌䥓彖啑剅彙䥄䭓††景⁯瀥†景⁸瀥†摢⁯瀥†⸥匪
쳌쳌쳌쳌쳌\Device\Harddisk%u"
0x24F3B: mov      edx, 2
0x24F40: lea      ecx, [rdx + 0x4b]
0x24F43: call     qword ptr [rip - 0xfd69]  ; → DbgPrintEx
0x24F49: mov      eax, dword ptr [rsp + 0x98]
0x24F50: cmp      ebx, eax
0x24F52: jne      0x25098
0x24F58: mov      r8d, eax
0x24F5B: lea      rdx, [rsp + 0x310]
0x24F63: mov      r14, qword ptr [rsp + 0xd0]
0x24F6B: mov      rcx, r14
0x24F6E: call     qword ptr [rip - 0xfdfc]  ; → RtlCompareMemory
0x24F74: mov      rdx, rax
0x24F77: mov      eax, dword ptr [rsp + 0x98]
0x24F7E: cmp      rdx, rax
0x24F81: je       0x250b7
0x24F87: jmp      0x25098
0x24F8C: bt       dword ptr [r12], 0x1f
0x24F92: jae      0x24fd3
0x24F94: call     0x12acc
0x24F99: mov      qword ptr [rsp + 0x38], rax
0x24F9E: mov      dword ptr [rsp + 0x30], ecx
0x24FA2: mov      rax, qword ptr [rsp + 0x108]
0x24FAA: mov      qword ptr [rsp + 0x28], rax
0x24FAF: mov      qword ptr [rsp + 0x20], rdi
0x24FB4: mov      r9, r14
0x24FB7: lea      r8, [rip + 0x19192]  ; → L"佉呃彌䥓彖啑剅彙䥄䭓††景⁯瀥†景⁸瀥†摢⁯瀥ⴠ┠㠰╘ੳ찀쳌쳌쳌佉呃彌䥓彖啑剅彙䥄䭓††景⁯瀥†景⁸瀥†睚畑牥卹浹潢楬䱣湩佫橢捥⡴┠⨮⁓ ‭〥堸猥
쳌쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†"
0x24FBE: mov      edx, 2
0x24FC3: lea      ecx, [rdx + 0x4b]
0x24FC6: call     qword ptr [rip - 0xfdec]  ; → DbgPrintEx
0x24FCC: mov      ecx, dword ptr [rsp + 0x90]
0x24FD3: cmp      ecx, 0xc0000010
0x24FD9: je       0x28e31
0x24FDF: jmp      0x25098
0x24FE4: bt       dword ptr [r12], 0x1f
0x24FEA: jae      0x25098
0x24FF0: mov      ecx, r14d
0x24FF3: call     0x12acc
0x24FF8: mov      qword ptr [rsp + 0x40], rax
0x24FFD: mov      dword ptr [rsp + 0x38], r14d
0x25002: lea      rax, [rsp + 0x310]
0x2500A: mov      qword ptr [rsp + 0x30], rax
0x2500F: mov      rax, qword ptr [rsp + 0x150]
0x25017: mov      qword ptr [rsp + 0x28], rax
0x2501C: mov      qword ptr [rsp + 0x20], rdi
0x25021: mov      r9, qword ptr [rsp + 0xb8]
0x25029: lea      r8, [rip + 0x19160]  ; → L"佉呃彌䥓彖啑剅彙䥄䭓††景⁯瀥†景⁸瀥†睚畑牥卹浹潢楬䱣湩佫橢捥⡴┠⨮⁓ ‭〥堸猥
쳌쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†摢⁯瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙"
0x25030: mov      edx, 2
0x25035: lea      ecx, [rdx + 0x4b]
0x25038: call     qword ptr [rip - 0xfe5e]  ; → DbgPrintEx
0x2503E: jmp      0x25098
0x25040: cmp      eax, 0xc0000034
0x25045: je       0x25098
0x25047: cmp      eax, 0xc000003a
0x2504C: je       0x25098
0x2504E: bt       dword ptr [r12], 0x1f
0x25054: jae      0x25098
0x25056: call     0x12acc
0x2505B: mov      qword ptr [rsp + 0x40], rax
0x25060: mov      dword ptr [rsp + 0x38], ecx
0x25064: lea      rax, [rsp + 0x310]
0x2506C: mov      qword ptr [rsp + 0x30], rax
0x25071: mov      qword ptr [rsp + 0x28], r14
0x25076: mov      qword ptr [rsp + 0x20], rdi
0x2507B: mov      r9, qword ptr [rsp + 0xb8]
0x25083: lea      r8, [rip + 0x19106]  ; → L"佉呃彌䥓彖啑剅彙䥄䭓††景⁯瀥†景⁸瀥†睚畑牥卹浹潢楬䱣湩佫橢捥⡴┠⨮⁓ ‭〥堸猥
쳌쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌佉呃彌䥓彖啑剅彙䥆䕌††景⁯瀥†景⁸瀥†摢⁯瀥†ⴥ㐲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙"
0x2508A: mov      edx, 2
0x2508F: lea      ecx, [rdx + 0x4b]
0x25092: call     qword ptr [rip - 0xfeb8]  ; → DbgPrintEx
0x25098: mov      eax, dword ptr [rsp + 0x9c]
0x2509F: add      eax, 1
0x250A2: mov      dword ptr [rsp + 0x9c], eax
0x250A9: cmp      eax, r13d
0x250AC: jae      0x28e31
0x250B2: jmp      0x24c6f
0x250B7: mov      edx, dword ptr [rsp + 0x94]
0x250BE: shr      rdx, 1
0x250C1: mov      eax, dword ptr [rsp + 0x9c]
0x250C8: mov      dword ptr [rsp + 0x30], eax
0x250CC: lea      rax, [rip + 0x1904d]  ; → L"\Device\Harddisk%u"
0x250D3: mov      qword ptr [rsp + 0x28], rax
0x250D8: mov      dword ptr [rsp + 0x20], 0x800
0x250E0: xor      r9d, r9d
0x250E3: lea      r8, [rsp + 0x128]
0x250EB: mov      rcx, r14
0x250EE: call     0x11008
0x250F3: mov      rdx, qword ptr [rsp + 0x128]
0x250FB: sub      rdx, r14
0x250FE: sar      rdx, 1
0x25101: add      rdx, rdx
0x25104: mov      qword ptr [r15 + 0x38], rdx
0x25108: jmp      0x28e31
0x2510D: mov      qword ptr [rsp + 0x118], rcx
0x25115: mov      word ptr [rsp + 0x110], bx
0x2511D: mov      word ptr [rsp + 0x112], bx
0x25125: mov      dword ptr [rsp + 0x240], 0x30
0x25130: mov      qword ptr [rsp + 0x248], rsi
0x25138: mov      eax, 0x40
0x2513D: mov      dword ptr [rsp + 0x258], eax
0x25144: lea      rax, [rsp + 0x110]
0x2514C: mov      qword ptr [rsp + 0x250], rax
0x25154: mov      qword ptr [rsp + 0x260], rsi
0x2515C: mov      qword ptr [rsp + 0x268], rsi
0x25164: lea      r8, [rsp + 0x240]
0x2516C: mov      edx, 0x80000000
0x25171: lea      rcx, [rsp + 0x140]
0x25179: call     qword ptr [rip - 0x100a7]  ; → ZwOpenSymbolicLinkObject
0x2517F: mov      r11d, eax
0x25182: mov      dword ptr [rsp + 0x90], eax
0x25189: cmp      eax, esi
0x2518B: jl       0x252bc
0x25191: bt       dword ptr [r12], 0xb
0x25197: jae      0x251f2
0x25199: movzx    ecx, word ptr [rsp + 0x110]
0x251A1: shr      rcx, 1
0x251A4: mov      rax, qword ptr [rsp + 0x118]
0x251AC: mov      qword ptr [rsp + 0x38], rax
0x251B1: mov      qword ptr [rsp + 0x30], rcx
0x251B6: mov      rax, qword ptr [rsp + 0x140]
0x251BE: mov      qword ptr [rsp + 0x28], rax
0x251C3: mov      rdi, qword ptr [rsp + 0xc0]
0x251CB: mov      qword ptr [rsp + 0x20], rdi
0x251D0: mov      r13, qword ptr [rsp + 0xb8]
0x251D8: mov      r9, r13
0x251DB: lea      r8, [rip + 0x18d7e]  ; → L"佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†汷⁨瀥†⸥匪
쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†睚畑牥卹浹潢楬䱣湩佫橢捥⡴┠⨮⁓ ‭〥堸猥
쳌쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†睚灏湥祓扭汯捩楌歮扏敪瑣 ⸥匪⤠†慆汩摥┠㠰╘ੳ찀쳌쳌쳌"
0x251E2: mov      edx, 2
0x251E7: lea      ecx, [rdx + 0x4b]
0x251EA: call     qword ptr [rip - 0x10010]  ; → DbgPrintEx
0x251F0: jmp      0x25202
0x251F2: mov      rdi, qword ptr [rsp + 0xc0]
0x251FA: mov      r13, qword ptr [rsp + 0xb8]
0x25202: mov      r14, qword ptr [rsp + 0xd0]
0x2520A: mov      qword ptr [rsp + 0x118], r14
0x25212: mov      eax, dword ptr [rsp + 0x94]
0x25219: mov      word ptr [rsp + 0x110], ax
0x25221: mov      word ptr [rsp + 0x112], ax
0x25229: lea      r8, [rsp + 0x94]
0x25231: lea      rdx, [rsp + 0x110]
0x25239: mov      rcx, qword ptr [rsp + 0x140]
0x25241: call     qword ptr [rip - 0x101e7]  ; → ZwQuerySymbolicLinkObject
0x25247: mov      r11d, eax
0x2524A: mov      dword ptr [rsp + 0x90], eax
0x25251: cmp      eax, esi
0x25253: jl       0x25263
0x25255: movzx    eax, word ptr [rsp + 0x110]
0x2525D: mov      qword ptr [r15 + 0x38], rax
0x25261: jmp      0x252a9
0x25263: bt       dword ptr [r12], 0x1f
0x25269: jae      0x252a9
0x2526B: mov      ecx, eax
0x2526D: call     0x12acc
0x25272: mov      rcx, rbx
0x25275: shr      rcx, 1
0x25278: mov      qword ptr [rsp + 0x40], rax
0x2527D: mov      dword ptr [rsp + 0x38], r11d
0x25282: mov      qword ptr [rsp + 0x30], r14
0x25287: mov      qword ptr [rsp + 0x28], rcx
0x2528C: mov      qword ptr [rsp + 0x20], rdi
0x25291: mov      r9, r13
0x25294: lea      r8, [rip + 0x18d05]  ; → L"佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†睚畑牥卹浹潢楬䱣湩佫橢捥⡴┠⨮⁓ ‭〥堸猥
쳌쳌쳌쳌쳌쳌佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†睚灏湥祓扭汯捩楌歮扏敪瑣 ⸥匪⤠†慆汩摥┠㠰╘ੳ찀쳌쳌쳌\Device\Harddisk%u\Partition0"
0x2529B: mov      edx, 2
0x252A0: lea      ecx, [rdx + 0x4b]
0x252A3: call     qword ptr [rip - 0x100c9]  ; → DbgPrintEx
0x252A9: mov      rcx, qword ptr [rsp + 0x140]
0x252B1: call     qword ptr [rip - 0x1017f]  ; → ZwClose
0x252B7: jmp      0x28e31
0x252BC: cmp      eax, 0xc0000034
0x252C1: je       0x28e31
0x252C7: cmp      eax, 0xc000003a
0x252CC: je       0x28e31
0x252D2: bt       dword ptr [r12], 0x1f
0x252D8: jae      0x28e31
0x252DE: mov      ecx, eax
0x252E0: call     0x12acc
0x252E5: mov      rcx, rbx
0x252E8: shr      rcx, 1
0x252EB: mov      qword ptr [rsp + 0x40], rax
0x252F0: mov      dword ptr [rsp + 0x38], r11d
0x252F5: mov      r14, qword ptr [rsp + 0xd0]
0x252FD: mov      qword ptr [rsp + 0x30], r14
0x25302: mov      qword ptr [rsp + 0x28], rcx
0x25307: mov      rdi, qword ptr [rsp + 0xc0]
0x2530F: mov      qword ptr [rsp + 0x20], rdi
0x25314: mov      r9, qword ptr [rsp + 0xb8]
0x2531C: lea      r8, [rip + 0x18cdd]  ; → L"佉呃彌䥓彖啑剅彙䥌䭎††景⁯瀥†景⁸瀥†睚灏湥祓扭汯捩楌歮扏敪瑣 ⸥匪⤠†慆汩摥┠㠰╘ੳ찀쳌쳌쳌\Device\Harddisk%u\Partition0"
0x25323: mov      edx, 2
0x25328: lea      ecx, [rdx + 0x4b]
0x2532B: call     qword ptr [rip - 0x10151]  ; → DbgPrintEx
0x25331: jmp      0x28e31
0x25336: cmp      ebx, 8  ← IOCTL 0x08 (RDMSR)
0x25339: jb       0x25369
0x2533B: movzx    edx, word ptr [rcx]
0x2533E: mov      eax, dword ptr [r14 + 4]
0x25342: out      dx, eax
0x25343: mov      qword ptr [r15 + 0x38], rsi
0x25347: mov      dword ptr [rsp + 0x90], esi
0x2534E: jmp      0x25369
0x25350: mov      dword ptr [rsp + 0x90], eax
0x25357: xor      esi, esi
0x25359: mov      r12, qword ptr [rsp + 0xe0]
0x25361: mov      r15, qword ptr [rsp + 0xe8]
0x25369: jmp      0x28e31
0x2536E: cmp      ebx, 4
0x25371: jb       0x253a2
0x25373: movzx    edx, word ptr [rcx]
0x25376: movzx    eax, word ptr [rcx + 2]
0x2537A: out      dx, ax
0x2537C: mov      qword ptr [r15 + 0x38], rsi
0x25380: mov      dword ptr [rsp + 0x90], esi
0x25387: jmp      0x253a2
0x25389: mov      dword ptr [rsp + 0x90], eax
0x25390: xor      esi, esi
0x25392: mov      r12, qword ptr [rsp + 0xe0]
0x2539A: mov      r15, qword ptr [rsp + 0xe8]
0x253A2: jmp      0x28e31
0x253A7: mov      dword ptr [rsp + 0x20], r13d
0x253AC: mov      r9d, ebx
0x253AF: mov      r8, r14
0x253B2: mov      rdx, r15
0x253B5: mov      rcx, r12
0x253B8: call     0x128c0
0x253BD: mov      dword ptr [rsp + 0x90], eax
0x253C4: jmp      0x28e31
0x253C9: mov      eax, edx
0x253CB: sub      eax, 0xe0
0x253D0: je       0x256a0
0x253D6: sub      eax, 4
0x253D9: je       0x25647
0x253DF: sub      eax, 4
0x253E2: je       0x255ed
0x253E8: sub      eax, 8
0x253EB: je       0x25555
0x253F1: sub      eax, 8
0x253F4: je       0x254ac
0x253FA: cmp      eax, 4
0x253FD: jne      0x28372
0x25403: cmp      ebx, 0xc  ← IOCTL 0x0C (WRMSR)
0x25406: jb       0x28e31
0x2540C: cmp      r13d, 0xc  ← IOCTL 0x0C (WRMSR)
0x25410: jb       0x28e31
0x25416: mov      r8d, dword ptr [r14]
0x25419: movzx    edx, word ptr [r14 + 6]
0x2541E: mov      rcx, r12
0x25421: call     0x2bb88
0x25426: cmp      eax, esi
0x25428: jl       0x25481
0x2542A: movzx    edx, word ptr [r14 + 6]
0x2542F: mov      al, byte ptr [r14 + 8]
0x25433: out      dx, al
0x25434: mov      r8d, dword ptr [r14]
0x25437: movzx    edx, word ptr [r14 + 6]
0x2543C: mov      rcx, r12
0x2543F: call     0x2bb88
0x25444: cmp      eax, esi
0x25446: jl       0x25481
0x25448: movzx    edx, word ptr [r14 + 4]
0x2544D: mov      al, byte ptr [r14 + 9]
0x25451: out      dx, al
0x25452: mov      r8d, dword ptr [r14]
0x25455: movzx    edx, word ptr [r14 + 6]
0x2545A: mov      rcx, r12
0x2545D: call     0x2bb88
0x25462: cmp      eax, esi
0x25464: jl       0x25481
0x25466: movzx    edx, word ptr [r14 + 4]
0x2546B: mov      al, byte ptr [r14 + 0xa]
0x2546F: out      dx, al
0x25470: mov      qword ptr [r15 + 0x38], 0xc
0x25478: mov      dword ptr [rsp + 0x90], esi
0x2547F: jmp      0x2548c
0x25481: mov      dword ptr [rsp + 0x90], 0xc00000b5
0x2548C: jmp      0x254a7
0x2548E: mov      dword ptr [rsp + 0x90], eax
0x25495: xor      esi, esi
0x25497: mov      r12, qword ptr [rsp + 0xe0]
0x2549F: mov      r15, qword ptr [rsp + 0xe8]
0x254A7: jmp      0x28e31
0x254AC: cmp      ebx, 0xc  ← IOCTL 0x0C (WRMSR)
0x254AF: jb       0x28e31
0x254B5: cmp      r13d, 0xc  ← IOCTL 0x0C (WRMSR)
0x254B9: jb       0x28e31
0x254BF: mov      r8d, dword ptr [r14]
0x254C2: movzx    edx, word ptr [r14 + 6]
0x254C7: mov      rcx, r12
0x254CA: call     0x2bb88
0x254CF: cmp      eax, esi
0x254D1: jl       0x2552a
0x254D3: movzx    edx, word ptr [r14 + 6]
0x254D8: mov      al, byte ptr [r14 + 8]
0x254DC: out      dx, al
0x254DD: mov      r8d, dword ptr [r14]
0x254E0: movzx    edx, word ptr [r14 + 6]
0x254E5: mov      rcx, r12
0x254E8: call     0x2bb88
0x254ED: cmp      eax, esi
0x254EF: jl       0x2552a
0x254F1: movzx    edx, word ptr [r14 + 4]
0x254F6: mov      al, byte ptr [r14 + 9]
0x254FA: out      dx, al
0x254FB: mov      r8d, dword ptr [r14]
0x254FE: movzx    edx, word ptr [r14 + 6]
0x25503: mov      rcx, r12
0x25506: call     0x2bacc
0x2550B: cmp      eax, esi
0x2550D: jl       0x2552a
0x2550F: movzx    edx, word ptr [r14 + 4]
0x25514: in       al, dx
0x25515: mov      byte ptr [r14 + 0xa], al
0x25519: mov      qword ptr [r15 + 0x38], 0xc
0x25521: mov      dword ptr [rsp + 0x90], esi
0x25528: jmp      0x25535
0x2552A: mov      dword ptr [rsp + 0x90], 0xc00000b5
0x25535: jmp      0x25550
0x25537: mov      dword ptr [rsp + 0x90], eax
0x2553E: xor      esi, esi
0x25540: mov      r12, qword ptr [rsp + 0xe0]
0x25548: mov      r15, qword ptr [rsp + 0xe8]
0x25550: jmp      0x28e31
0x25555: cmp      ebx, 0xb
0x25558: jb       0x28e31
0x2555E: cmp      r13d, ebx
0x25561: jb       0x28e31
0x25567: lea      eax, [rbx - 0xa]
0x2556A: mov      dword ptr [rsp + 0x94], eax
0x25571: cmp      eax, r8d
0x25574: ja       0x28e31
0x2557A: cmp      dword ptr [r14], 0xfa
0x25581: ja       0x28e31
0x25587: mov      r13d, esi
0x2558A: mov      dword ptr [rsp + 0xb0], esi
0x25591: cmp      eax, esi
0x25593: jbe      0x255dd
0x25595: add      r14, 0xa
0x25599: movzx    edx, word ptr [rdi + 4]
0x2559D: mov      al, byte ptr [rdi + 8]
0x255A0: out      dx, al
0x255A1: movzx    edx, word ptr [rdi + 6]
0x255A5: mov      al, byte ptr [r14]
0x255A8: out      dx, al
0x255A9: mov      edx, dword ptr [rdi]
0x255AB: mov      rcx, r12
0x255AE: call     0x2bc50
0x255B3: movzx    edx, word ptr [rdi + 4]
0x255B7: mov      al, byte ptr [rdi + 9]
0x255BA: out      dx, al
0x255BB: movzx    edx, word ptr [rdi + 6]
0x255BF: in       al, dx
0x255C0: mov      byte ptr [r14], al
0x255C3: add      r13d, 1
0x255C7: add      r14, 1
0x255CB: cmp      r13d, dword ptr [rsp + 0x94]
0x255D3: jb       0x25599
0x255D5: mov      dword ptr [rsp + 0xb0], r13d
0x255DD: mov      qword ptr [r15 + 0x38], rbx
0x255E1: mov      dword ptr [rsp + 0x90], esi
0x255E8: jmp      0x28e31
0x255ED: cmp      ebx, 0x20
0x255F0: jb       0x28e31
0x255F6: cmp      r13d, 0x20
0x255FA: jb       0x28e31
0x25600: lea      rax, [r14 + 0x18]
0x25604: lea      r9, [r14 + 0x10]
0x25608: mov      qword ptr [rsp + 0x20], rax
0x2560D: mov      r8, qword ptr [r14 + 8]
0x25611: mov      edx, dword ptr [r14 + 4]
0x25615: mov      ecx, dword ptr [r14]
0x25618: call     qword ptr [rip - 0x1061e]  ; → HalTranslateBusAddress
0x2561E: cmp      al, sil
0x25621: je       0x25637
0x25623: mov      qword ptr [r15 + 0x38], 0x20
0x2562B: mov      dword ptr [rsp + 0x90], esi
0x25632: jmp      0x28e31
0x25637: mov      dword ptr [rsp + 0x90], 0xc0040036
0x25642: jmp      0x28e31
0x25647: mov      eax, dword ptr [r12 + 0x1b8]
0x2564F: sub      eax, r12d
0x25652: mov      ecx, 0x648
0x25657: sub      eax, ecx
0x25659: cmp      r13d, eax
0x2565C: jb       0x28e31
0x25662: mov      eax, dword ptr [r12 + 0x1b0]
0x2566A: sub      eax, r12d
0x2566D: sub      eax, ecx
0x2566F: mov      dword ptr [rsp + 0x94], eax
0x25676: mov      r8d, eax
0x25679: lea      rdx, [r12 + 0x648]
0x25681: mov      rcx, r14
0x25684: call     0x12e10
0x25689: mov      edx, dword ptr [rsp + 0x94]
0x25690: mov      qword ptr [r15 + 0x38], rdx
0x25694: mov      dword ptr [rsp + 0x90], esi
0x2569B: jmp      0x28e31
0x256A0: mov      ebx, 0x6c
0x256A5: cmp      r13d, ebx
0x256A8: jb       0x28e31
0x256AE: mov      rcx, r14
0x256B1: lea      rdx, [r12 + 0x5d8]
0x256B9: mov      r8, rbx
0x256BC: call     0x12e10
0x256C1: mov      qword ptr [r15 + 0x38], rbx
0x256C5: mov      dword ptr [rsp + 0x90], esi
0x256CC: jmp      0x28e31
0x256D1: cmp      r10, rsi
0x256D4: je       0x25712
0x256D6: mov      rdx, qword ptr [r10 + 0x10]
0x256DA: mov      qword ptr [rsp + 0xa8], rdx
0x256E2: cmp      rdx, rsi
0x256E5: je       0x25712
0x256E7: lea      rax, [r15 + 0x30]
0x256EB: mov      qword ptr [rsp + 0x28], rax
0x256F0: mov      dword ptr [rsp + 0x20], 1
0x256F8: mov      r9d, r13d
0x256FB: mov      r8, r14
0x256FE: mov      rcx, r12
0x25701: call     0x2fdec
0x25706: mov      dword ptr [rsp + 0x90], eax
0x2570D: jmp      0x28e31
0x25712: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x2571D: jmp      0x28e31
0x25722: cmp      edx, 0x1ec
0x25728: ja       0x26578
0x2572E: cmp      edx, 0x1ec
0x25734: je       0x2653f
0x2573A: cmp      edx, 0x194
0x25740: ja       0x26048
0x25746: cmp      edx, 0x194
0x2574C: je       0x25fe4
0x25752: mov      eax, 0x160
0x25757: cmp      edx, eax
0x25759: ja       0x25c3e
0x2575F: cmp      edx, eax
0x25761: je       0x25c19
0x25767: mov      eax, edx
0x25769: sub      eax, 0x104
0x2576E: je       0x25bcc
0x25774: sub      eax, 0x2c
0x25777: je       0x25ae1
0x2577D: sub      eax, 4
0x25780: je       0x25a22
0x25786: sub      eax, 4
0x25789: je       0x2597d
0x2578F: sub      eax, 4
0x25792: je       0x25924
0x25798: cmp      eax, 8  ← IOCTL 0x08 (RDMSR)
0x2579B: jne      0x28372
0x257A1: cmp      ebx, r8d
0x257A4: jae      0x257df
0x257A6: bt       dword ptr [r12], 0x1f
0x257AC: jae      0x257cf
0x257AE: mov      qword ptr [rsp + 0x30], r8
0x257B3: mov      dword ptr [rsp + 0x28], ebx
0x257B7: mov      qword ptr [rsp + 0x20], r10
0x257BC: lea      r8, [rip + 0x184cd]  ; → L"佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†摡⁯瀥†楳⁧⸥猸†瑣⁬〥堸†瑳⁳〥堸猥
佉呃彌䥓彖塏䕓䥍"
0x257C3: lea      edx, [rax - 6]
0x257C6: mov      ecx, r11d
0x257C9: call     qword ptr [rip - 0x105ef]  ; → DbgPrintEx
0x257CF: mov      dword ptr [rsp + 0x90], 0xc0000023
0x257DA: jmp      0x28e31
0x257DF: mov      eax, 0x210
0x257E4: cmp      r13d, eax
0x257E7: jae      0x25825
0x257E9: bt       dword ptr [r12], 0x1f
0x257EF: jae      0x25815
0x257F1: mov      qword ptr [rsp + 0x30], rax
0x257F6: mov      dword ptr [rsp + 0x28], r13d
0x257FB: mov      qword ptr [rsp + 0x20], r10
0x25800: lea      r8, [rip + 0x184d9]  ; → L"佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†摡⁯瀥†楳⁧⸥猸†瑣⁬〥堸†瑳⁳〥堸猥
佉呃彌䥓彖塏䕓䥍›灵㸭䑶癥††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭䑶癥††䘠楡敬⁤〥堸猥
쳌"
0x25807: mov      edx, 2
0x2580C: mov      ecx, r11d
0x2580F: call     qword ptr [rip - 0x10635]  ; → DbgPrintEx
0x25815: mov      dword ptr [rsp + 0x90], 0xc0000023
0x25820: jmp      0x28e31
0x25825: cmp      r10, rsi
0x25828: je       0x28e31
0x2582E: cmp      byte ptr [r10 + 0x2e], 0xff
0x25833: je       0x28e31
0x25839: mov      r8, qword ptr [r10 + 8]
0x2583D: mov      qword ptr [rsp + 0x108], r8
0x25845: cmp      r8, rsi
0x25848: je       0x28e31
0x2584E: mov      r9, qword ptr [r10 + 0x18]
0x25852: mov      qword ptr [rsp + 0xa8], r9
0x2585A: cmp      r9, rsi
0x2585D: je       0x28e31
0x25863: lea      rax, [r15 + 0x30]
0x25867: lea      ecx, [rbx - 0x10]
0x2586A: lea      rdx, [r14 + 0x10]
0x2586E: mov      rbx, qword ptr [r8 + 8]
0x25872: add      rbx, 0x38
0x25876: mov      qword ptr [rsp + 0x50], rax
0x2587B: mov      dword ptr [rsp + 0x48], r13d
0x25880: mov      dword ptr [rsp + 0x40], ecx
0x25884: mov      qword ptr [rsp + 0x38], rdx
0x25889: mov      qword ptr [rsp + 0x30], rbx
0x2588E: mov      qword ptr [rsp + 0x28], r9
0x25893: mov      qword ptr [rsp + 0x20], r14
0x25898: mov      r9d, 0x4d008
0x2589E: mov      r8, r10
0x258A1: mov      rdx, r12
0x258A4: lea      rcx, [rip + 0x17b75]  ; → L"佉呃彌䍓䥓䵟义偉剏T쳌쳌쳌쳌쳌쳌佉呃彌䍓䥓䵟义偉剏⁔††景⁯瀥†景⁸瀥†摡⁯瀥†畢⁦瀥†灩⁬ⴥ甴†灯⁬ⴥ甴†敬⁮甥
쳌쳌쳌쳌쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓†景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†湩異⁴畢"
0x258AB: call     0x3c114
0x258B0: mov      ecx, eax
0x258B2: mov      dword ptr [rsp + 0x90], eax
0x258B9: cmp      eax, esi
0x258BB: jge      0x28e31
0x258C1: bt       dword ptr [r12], 0x1f
0x258C7: jae      0x28e31
0x258CD: call     0x12acc
0x258D2: mov      qword ptr [rsp + 0x48], rax
0x258D7: mov      dword ptr [rsp + 0x40], ecx
0x258DB: mov      eax, dword ptr [r14 + 8]
0x258DF: mov      dword ptr [rsp + 0x38], eax
0x258E3: mov      qword ptr [rsp + 0x30], r14
0x258E8: mov      rax, qword ptr [rsp + 0xa8]
0x258F0: mov      qword ptr [rsp + 0x28], rax
0x258F5: mov      rdi, qword ptr [rsp + 0xc0]
0x258FD: mov      qword ptr [rsp + 0x20], rdi
0x25902: mov      r9, qword ptr [rsp + 0xb8]
0x2590A: lea      r8, [rip + 0x1841f]  ; → L"佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†摡⁯瀥†楳⁧⸥猸†瑣⁬〥堸†瑳⁳〥堸猥
佉呃彌䥓彖塏䕓䥍›灵㸭䑶癥††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭䑶癥††䘠楡敬⁤〥堸猥
쳌佉呃彌䥓彖塏䕓䥍›灵㸭䙶硩††┠㠰੘찀쳌쳌쳌쳌쳌佉呃彌䥓彖塏䕓䥍›灵㸭䙶硩††䘠"
0x25911: mov      edx, 2
0x25916: lea      ecx, [rdx + 0x4b]
0x25919: call     qword ptr [rip - 0x1073f]  ; → DbgPrintEx
0x2591F: jmp      0x28e31
0x25924: mov      qword ptr [rsp + 0x20], rsi
0x25929: xor      r9d, r9d
0x2592C: xor      r8d, r8d
0x2592F: lea      edx, [r9 + 6]
0x25933: lea      rcx, [r12 + 0x568]
0x2593B: call     qword ptr [rip - 0x107e9]  ; → KeWaitForSingleObject
0x25941: mov      dword ptr [rsp + 0x90], eax
0x25948: cmp      eax, esi
0x2594A: jne      0x28e31
0x25950: mov      rdx, rsi
0x25953: xchg     qword ptr [r12 + 0x10d0], rdx
0x2595B: cmp      rdx, rsi
0x2595E: je       0x25968
0x25960: mov      rcx, r12
0x25963: call     0x2e34c
0x25968: xor      edx, edx
0x2596A: lea      rcx, [r12 + 0x568]
0x25972: call     qword ptr [rip - 0x10878]  ; → KeReleaseMutex
0x25978: jmp      0x28e31
0x2597D: cmp      r10, rsi
0x25980: je       0x25a12
0x25986: mov      rax, qword ptr [r10 + 0x10]
0x2598A: mov      qword ptr [rsp + 0xa8], rax
0x25992: cmp      rax, rsi
0x25995: je       0x25a12
0x25997: cmp      dword ptr [rax + 0x48], 0x32
0x2599B: jne      0x25a12
0x2599D: mov      qword ptr [rsp + 0x20], rsi
0x259A2: xor      r9d, r9d
0x259A5: xor      r8d, r8d
0x259A8: lea      edx, [r9 + 6]
0x259AC: lea      rcx, [r12 + 0x568]
0x259B4: call     qword ptr [rip - 0x10862]  ; → KeWaitForSingleObject
0x259BA: mov      dword ptr [rsp + 0x90], eax
0x259C1: cmp      eax, esi
0x259C3: jne      0x28e31
0x259C9: mov      rdx, rsi
0x259CC: xchg     qword ptr [r12 + 0x10d0], rdx
0x259D4: cmp      rdx, rsi
0x259D7: je       0x259e1
0x259D9: mov      rcx, r12
0x259DC: call     0x2e34c
0x259E1: mov      rdx, qword ptr [rsp + 0xa8]
0x259E9: mov      rdx, qword ptr [rdx + 8]
0x259ED: mov      rcx, r12
0x259F0: call     0x2df94
0x259F5: mov      qword ptr [r12 + 0x10d0], rax
0x259FD: xor      edx, edx
0x259FF: lea      rcx, [r12 + 0x568]
0x25A07: call     qword ptr [rip - 0x1090d]  ; → KeReleaseMutex
0x25A0D: jmp      0x28e31
0x25A12: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x25A1D: jmp      0x28e31
0x25A22: cmp      r13d, 8  ← IOCTL 0x08 (RDMSR)
0x25A26: jb       0x28e31
0x25A2C: test     byte ptr [r12 + 4], 8
0x25A32: je       0x25a4e
0x25A34: lea      r8, [rip + 0x18895]  ; → L"佉呃彌䥓彖䍁䥐䡟䅅⁄
쳌쳌쳌쳌쳌䕇彔剐䍏卅体归䉏彊义但찀쳌쳌쳌쳌䍁䥐䕟啎彍䡃䱉剄久┠㈰⁘┠⁵┠╣╣╣⁣漠潦┠⁰漠硦┠⁰┠⁳瀥†灩┠⁰ⴥ甲†灯┠⁰甥
쳌쳌쳌쳌쳌쳌䍁䥐䕟啎彍䡃䱉剄久찀쳌쳌쳌쳌쳌쳌䍁䥐䕟䅖彌䕍䡔䑏†㤸㄰찀쳌쳌쳌쳌ⴥ㈲㈮猲†景⁯瀥†景⁸瀥†猥┠⁰"
0x25A3B: mov      edx, 2
0x25A40: mov      ecx, r11d
0x25A43: call     qword ptr [rip - 0x10869]  ; → DbgPrintEx
0x25A49: call     0x1314a
0x25A4E: mov      rdi, qword ptr [rsp + 0xc0]
0x25A56: cmp      rdi, rsi
0x25A59: je       0x25ad1
0x25A5B: mov      rdx, qword ptr [rdi + 0x10]
0x25A5F: mov      qword ptr [rsp + 0xa8], rdx
0x25A67: cmp      rdx, rsi
0x25A6A: je       0x25ad1
0x25A6C: mov      rcx, r12
0x25A6F: call     0x2fc58
0x25A74: mov      rdx, rax
0x25A77: cmp      rax, rsi
0x25A7A: je       0x25ad1
0x25A7C: mov      ecx, dword ptr [rsp + 0x94]
0x25A83: mov      eax, 0x90
0x25A88: cmp      ecx, eax
0x25A8A: cmova    ecx, eax
0x25A8D: mov      dword ptr [rsp + 0x94], ecx
0x25A94: mov      r8d, ecx
0x25A97: mov      rcx, r14
0x25A9A: call     0x12e10
0x25A9F: mov      edx, dword ptr [rsp + 0x94]
0x25AA6: mov      qword ptr [r15 + 0x38], rdx
0x25AAA: mov      dword ptr [rsp + 0x90], esi
0x25AB1: jmp      0x25acc
0x25AB3: mov      dword ptr [rsp + 0x90], eax
0x25ABA: xor      esi, esi
0x25ABC: mov      r12, qword ptr [rsp + 0xe0]
0x25AC4: mov      r15, qword ptr [rsp + 0xe8]
0x25ACC: jmp      0x28e31
0x25AD1: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x25ADC: jmp      0x28e31
0x25AE1: cmp      r13d, 8  ← IOCTL 0x08 (RDMSR)
0x25AE5: jb       0x28e31
0x25AEB: cmp      r10, rsi
0x25AEE: je       0x25bbc
0x25AF4: mov      rdx, qword ptr [r10 + 0x10]
0x25AF8: mov      qword ptr [rsp + 0xa8], rdx
0x25B00: cmp      rdx, rsi
0x25B03: je       0x25bbc
0x25B09: cmp      dword ptr [rdx + 0x48], 0x32
0x25B0D: jne      0x25bbc
0x25B13: cmp      dword ptr [r12 + 0x78], 0x1dc0
0x25B1C: jae      0x25b31
0x25B1E: mov      eax, 0x260
0x25B23: cmp      r13d, eax
0x25B26: jbe      0x25b31
0x25B28: mov      dword ptr [rsp + 0x94], eax
0x25B2F: jmp      0x25b7b
0x25B31: cmp      dword ptr [r12 + 0x78], 0x2400
0x25B3A: jae      0x25b4f
0x25B3C: mov      eax, 0x2c0
0x25B41: cmp      r13d, eax
0x25B44: jbe      0x25b4f
0x25B46: mov      dword ptr [rsp + 0x94], eax
0x25B4D: jmp      0x25b7b
0x25B4F: cmp      dword ptr [r12 + 0x78], 0x2590
0x25B58: jae      0x25b66
0x25B5A: mov      eax, 0x2d0
0x25B5F: cmp      r13d, eax
0x25B62: cmova    r13d, eax
0x25B66: mov      eax, r13d
0x25B69: mov      ecx, 0x380
0x25B6E: cmp      r13d, ecx
0x25B71: cmova    eax, ecx
0x25B74: mov      dword ptr [rsp + 0x94], eax
0x25B7B: mov      r8d, eax
0x25B7E: mov      rdx, qword ptr [rdx + 0x40]
0x25B82: mov      rcx, r14
0x25B85: call     0x12e10
0x25B8A: mov      edx, dword ptr [rsp + 0x94]
0x25B91: mov      qword ptr [r15 + 0x38], rdx
0x25B95: mov      dword ptr [rsp + 0x90], esi
0x25B9C: jmp      0x25bb7
0x25B9E: mov      dword ptr [rsp + 0x90], eax
0x25BA5: xor      esi, esi
0x25BA7: mov      r12, qword ptr [rsp + 0xe0]
0x25BAF: mov      r15, qword ptr [rsp + 0xe8]
0x25BB7: jmp      0x28e31
0x25BBC: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x25BC7: jmp      0x28e31
0x25BCC: cmp      r10, rsi
0x25BCF: je       0x25c09
0x25BD1: mov      rdx, qword ptr [r10 + 0x10]
0x25BD5: mov      qword ptr [rsp + 0xa8], rdx
0x25BDD: cmp      rdx, rsi
0x25BE0: je       0x25c09
0x25BE2: lea      rax, [r15 + 0x30]
0x25BE6: mov      qword ptr [rsp + 0x28], rax
0x25BEB: mov      dword ptr [rsp + 0x20], esi
0x25BEF: mov      r9d, r13d
0x25BF2: mov      r8, r14
0x25BF5: mov      rcx, r12
0x25BF8: call     0x2fdec
0x25BFD: mov      dword ptr [rsp + 0x90], eax
0x25C04: jmp      0x28e31
0x25C09: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x25C14: jmp      0x28e31
0x25C19: cmp      r13d, 8  ← IOCTL 0x08 (RDMSR)
0x25C1D: jb       0x28e31
0x25C23: lea      r8, [r15 + 0x30]
0x25C27: mov      rdx, r14
0x25C2A: mov      rcx, r12
0x25C2D: call     0x11b2c
0x25C32: mov      dword ptr [rsp + 0x90], eax
0x25C39: jmp      0x28e31
0x25C3E: mov      eax, edx
0x25C40: sub      eax, 0x170
0x25C45: je       0x25f4e
0x25C4B: sub      eax, r8d
0x25C4E: je       0x25e63
0x25C54: sub      eax, 4
0x25C57: je       0x25dff
0x25C5D: sub      eax, 4
0x25C60: je       0x25d3c
0x25C66: sub      eax, 4
0x25C69: je       0x25cd8
0x25C6B: cmp      eax, 4
0x25C6E: jne      0x28372
0x25C74: cmp      r13d, 0x7f
0x25C78: jbe      0x25cc8
0x25C7A: cmp      r10, rsi
0x25C7D: je       0x25cc8
0x25C7F: mov      rax, qword ptr [r10 + 8]
0x25C83: mov      qword ptr [rsp + 0xa8], rax
0x25C8B: cmp      rax, rsi
0x25C8E: je       0x25cc8
0x25C90: lea      rdx, [rsp + 0x98]
0x25C98: mov      qword ptr [rsp + 0x20], rdx
0x25C9D: mov      r9, rcx
0x25CA0: mov      r8d, r13d
0x25CA3: mov      edx, 1
0x25CA8: mov      rcx, rax
0x25CAB: call     qword ptr [rip - 0x10ad9]  ; → IoGetDeviceProperty
0x25CB1: mov      dword ptr [rsp + 0x90], eax
0x25CB8: mov      eax, dword ptr [rsp + 0x98]
0x25CBF: mov      qword ptr [r15 + 0x38], rax
0x25CC3: jmp      0x28e31
0x25CC8: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x25CD3: jmp      0x28e31
0x25CD8: cmp      r13d, 0x7f
0x25CDC: jbe      0x25d2c
0x25CDE: cmp      r10, rsi
0x25CE1: je       0x25d2c
0x25CE3: mov      rax, qword ptr [r10 + 8]
0x25CE7: mov      qword ptr [rsp + 0xa8], rax
0x25CEF: cmp      rax, rsi
0x25CF2: je       0x25d2c
0x25CF4: lea      rdx, [rsp + 0x98]
0x25CFC: mov      qword ptr [rsp + 0x20], rdx
0x25D01: mov      r9, rcx
0x25D04: mov      r8d, r13d
0x25D07: mov      edx, 0xf
0x25D0C: mov      rcx, rax
0x25D0F: call     qword ptr [rip - 0x10b3d]  ; → IoGetDeviceProperty
0x25D15: mov      dword ptr [rsp + 0x90], eax
0x25D1C: mov      eax, dword ptr [rsp + 0x98]
0x25D23: mov      qword ptr [r15 + 0x38], rax
0x25D27: jmp      0x28e31
0x25D2C: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x25D37: jmp      0x28e31
0x25D3C: cmp      r13d, 0x7f
0x25D40: jbe      0x25def
0x25D46: cmp      r10, rsi
0x25D49: je       0x25def
0x25D4F: mov      rax, qword ptr [r10 + 8]
0x25D53: mov      qword ptr [rsp + 0xa8], rax
0x25D5B: cmp      rax, rsi
0x25D5E: je       0x25def
0x25D64: lea      rdx, [rsp + 0x98]
0x25D6C: mov      qword ptr [rsp + 0x20], rdx
0x25D71: mov      r9, rcx
0x25D74: mov      r8d, r13d
0x25D77: mov      edx, 9
0x25D7C: mov      rcx, rax
0x25D7F: call     qword ptr [rip - 0x10bad]  ; → IoGetDeviceProperty
0x25D85: mov      dword ptr [rsp + 0x90], eax
0x25D8C: cmp      eax, esi
0x25D8E: jl       0x25d9b
0x25D90: mov      eax, dword ptr [rsp + 0x98]
0x25D97: cmp      eax, esi
0x25D99: jne      0x25de6
0x25D9B: lea      rax, [rsp + 0x98]
0x25DA3: mov      qword ptr [rsp + 0x20], rax
0x25DA8: mov      r9, qword ptr [rsp + 0xd0]
0x25DB0: mov      r8d, dword ptr [rsp + 0x94]
0x25DB8: xor      edx, edx
0x25DBA: mov      rcx, qword ptr [rsp + 0xa8]
0x25DC2: call     qword ptr [rip - 0x10bf0]  ; → IoGetDeviceProperty
0x25DC8: mov      dword ptr [rsp + 0x90], eax
0x25DCF: cmp      eax, esi
0x25DD1: jl       0x28e31
0x25DD7: mov      eax, dword ptr [rsp + 0x98]
0x25DDE: cmp      eax, esi
0x25DE0: je       0x28e31
0x25DE6: mov      qword ptr [r15 + 0x38], rax
0x25DEA: jmp      0x28e31
0x25DEF: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x25DFA: jmp      0x28e31
0x25DFF: cmp      r13d, 0x7f
0x25E03: jbe      0x25e53
0x25E05: cmp      r10, rsi
0x25E08: je       0x25e53
0x25E0A: mov      rax, qword ptr [r10 + 8]
0x25E0E: mov      qword ptr [rsp + 0xa8], rax
0x25E16: cmp      rax, rsi
0x25E19: je       0x25e53
0x25E1B: lea      rdx, [rsp + 0x98]
0x25E23: mov      qword ptr [rsp + 0x20], rdx
0x25E28: mov      r9, rcx
0x25E2B: mov      r8d, r13d
0x25E2E: mov      edx, 5
0x25E33: mov      rcx, rax
0x25E36: call     qword ptr [rip - 0x10c64]  ; → IoGetDeviceProperty
0x25E3C: mov      dword ptr [rsp + 0x90], eax
0x25E43: mov      eax, dword ptr [rsp + 0x98]
0x25E4A: mov      qword ptr [r15 + 0x38], rax
0x25E4E: jmp      0x28e31
0x25E53: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x25E5E: jmp      0x28e31
0x25E63: cmp      r13d, 0x200
0x25E6A: jb       0x28e31
0x25E70: mov      qword ptr [rsp + 0x20], rsi
0x25E75: xor      r9d, r9d
0x25E78: xor      r8d, r8d
0x25E7B: lea      edx, [r9 + 6]
0x25E7F: lea      rcx, [r12 + 0x568]
0x25E87: call     qword ptr [rip - 0x10d35]  ; → KeWaitForSingleObject
0x25E8D: mov      dword ptr [rsp + 0x90], eax
0x25E94: cmp      eax, esi
0x25E96: jne      0x28e31
0x25E9C: mov      r13d, dword ptr [rsp + 0x94]
0x25EA4: mov      rdx, qword ptr [r12 + 0x10d0]
0x25EAC: cmp      rdx, rsi
0x25EAF: je       0x25ef4
0x25EB1: movsxd   r14, dword ptr [rdx + 0xc]
0x25EB5: cmp      r13d, r14d
0x25EB8: jae      0x25ec7
0x25EBA: mov      dword ptr [rsp + 0x90], 0xc0000206
0x25EC5: jmp      0x25f39
0x25EC7: mov      ebx, r14d
0x25ECA: add      rdx, 0x10
0x25ECE: mov      r8d, r14d
0x25ED1: mov      rdi, qword ptr [rsp + 0xd0]
0x25ED9: mov      rcx, rdi
0x25EDC: call     0x12e10
0x25EE1: add      qword ptr [r15 + 0x38], rbx
0x25EE5: mov      rax, r14
0x25EE8: shr      rax, 1
0x25EEB: lea      rdi, [rdi + rax*2]
0x25EEF: sub      r13d, r14d
0x25EF2: jmp      0x25efc
0x25EF4: mov      rdi, qword ptr [rsp + 0xd0]
0x25EFC: mov      rdx, qword ptr [r12 + 0x10d8]
0x25F04: cmp      rdx, rsi
0x25F07: je       0x25f32
0x25F09: cmp      r13d, dword ptr [rdx + 0xc]
0x25F0D: jae      0x25f1c
0x25F0F: mov      dword ptr [rsp + 0x90], 0xc0000206
0x25F1A: jmp      0x25f39
0x25F1C: mov      ebx, dword ptr [rdx + 0xc]
0x25F1F: add      rdx, 0x10
0x25F23: mov      r8, rbx
0x25F26: mov      rcx, rdi
0x25F29: call     0x12e10
0x25F2E: add      qword ptr [r15 + 0x38], rbx
0x25F32: mov      dword ptr [rsp + 0x90], esi
0x25F39: xor      edx, edx
0x25F3B: lea      rcx, [r12 + 0x568]
0x25F43: call     qword ptr [rip - 0x10e49]  ; → KeReleaseMutex
0x25F49: jmp      0x28e31
0x25F4E: cmp      r13d, 4
0x25F52: jb       0x28e31
0x25F58: test     byte ptr [r12], 0x20
0x25F5D: je       0x25f74
0x25F5F: lea      r8, [rip + 0x16e5a]  ; → L"佉呃彌䥓彖䕇彔偃录剃‰†景⁯瀥
佉呃彌䥓彖䍐䉉单††††獤⁴瀥†慰⁤〥堸╟㠰⁘洠灡┠⁰猠捲┠⁰氠湥┠㐰⁘漠晦┠㐰੘찀쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䵁彄䍐敉†††灶⁷甥㸠眠扤┠Ⱶ戠摡椠汰┠㈰⁘牯℠‽灯⁬〥堲†瑳⁳〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭"
0x25F66: mov      edx, 2
0x25F6B: mov      ecx, r11d
0x25F6E: call     qword ptr [rip - 0x10d94]  ; → DbgPrintEx
0x25F74: mov      rax, cr0
0x25F77: mov      dword ptr [rsp + 0xd8], eax
0x25F7E: mov      dword ptr [r14], eax
0x25F81: mov      qword ptr [r15 + 0x38], 4
0x25F89: mov      dword ptr [rsp + 0x90], esi
0x25F90: jmp      0x25fdf
0x25F92: mov      ecx, eax
0x25F94: mov      dword ptr [rsp + 0x90], eax
0x25F9B: mov      r12, qword ptr [rsp + 0xe0]
0x25FA3: test     byte ptr [r12], 0x20
0x25FA8: je       0x25fd5
0x25FAA: call     0x12acc
0x25FAF: mov      qword ptr [rsp + 0x28], rax
0x25FB4: mov      dword ptr [rsp + 0x20], ecx
0x25FB8: mov      r9, qword ptr [rsp + 0xb8]
0x25FC0: lea      r8, [rip + 0x16df9]  ; → L"佉呃彌䥓彖䕇彔偃录剃‰†景⁯瀥
佉呃彌䥓彖䍐䉉单††††獤⁴瀥†慰⁤〥堸╟㠰⁘洠灡┠⁰猠捲┠⁰氠湥┠㐰⁘漠晦┠㐰੘찀쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䵁彄䍐敉†††灶⁷甥㸠眠扤┠Ⱶ戠摡椠汰┠㈰⁘牯℠‽灯⁬〥堲†瑳⁳〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭"
0x25FC7: mov      edx, 2
0x25FCC: lea      ecx, [rdx + 0x4b]
0x25FCF: call     qword ptr [rip - 0x10df5]  ; → DbgPrintEx
0x25FD5: xor      esi, esi
0x25FD7: mov      r15, qword ptr [rsp + 0xe8]
0x25FDF: jmp      0x28e31
0x25FE4: cmp      r13d, 0x7f
0x25FE8: jbe      0x26038
0x25FEA: cmp      r10, rsi
0x25FED: je       0x26038
0x25FEF: mov      rax, qword ptr [r10 + 8]
0x25FF3: mov      qword ptr [rsp + 0xa8], rax
0x25FFB: cmp      rax, rsi
0x25FFE: je       0x26038
0x26000: lea      rdx, [rsp + 0x98]
0x26008: mov      qword ptr [rsp + 0x20], rdx
0x2600D: mov      r9, rcx
0x26010: mov      r8d, r13d
0x26013: mov      edx, 1
0x26018: mov      rcx, rax
0x2601B: call     qword ptr [rip - 0x10e49]  ; → IoGetDeviceProperty
0x26021: mov      dword ptr [rsp + 0x90], eax
0x26028: mov      eax, dword ptr [rsp + 0x98]
0x2602F: mov      qword ptr [r15 + 0x38], rax
0x26033: jmp      0x28e31
0x26038: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x26043: jmp      0x28e31
0x26048: cmp      edx, 0x1c8
0x2604E: ja       0x263f6
0x26054: cmp      edx, 0x1c8
0x2605A: je       0x2638f
0x26060: mov      eax, edx
0x26062: sub      eax, 0x198
0x26067: je       0x2632b
0x2606D: sub      eax, 4
0x26070: je       0x262c7
0x26076: sub      eax, 0x1c
0x26079: je       0x2626f
0x2607F: sub      eax, 4
0x26082: je       0x261b6
0x26088: sub      eax, 4
0x2608B: je       0x26101
0x2608D: cmp      eax, 4
0x26090: jne      0x28372
0x26096: cmp      ebx, 1
0x26099: jb       0x260fc
0x2609B: cmp      ebx, r13d
0x2609E: ja       0x260fc
0x260A0: cmp      r13d, 0x100
0x260A7: ja       0x260fc
0x260A9: lea      rcx, [r14 + rbx]
0x260AD: cmp      r14, rcx
0x260B0: jae      0x260d0
0x260B2: mov      dx, 0xcd6
0x260B6: mov      al, byte ptr [r14]
0x260B9: out      dx, al
0x260BA: mov      dx, 0xcd7
0x260BE: in       al, dx
0x260BF: mov      byte ptr [r14], al
0x260C2: add      r14, 1
0x260C6: mov      qword ptr [rsp + 0x148], r14
0x260CE: jmp      0x260ad
0x260D0: sub      r14d, edi
0x260D3: mov      eax, r14d
0x260D6: mov      qword ptr [r15 + 0x38], rax
0x260DA: mov      dword ptr [rsp + 0x90], esi
0x260E1: jmp      0x260fc
0x260E3: mov      dword ptr [rsp + 0x90], eax
0x260EA: xor      esi, esi
0x260EC: mov      r12, qword ptr [rsp + 0xe0]
0x260F4: mov      r15, qword ptr [rsp + 0xe8]
0x260FC: jmp      0x28e31
0x26101: cmp      ebx, 1
0x26104: jb       0x261b1
0x2610A: lea      eax, [r13 - 1]
0x2610E: cmp      eax, 0xff
0x26113: ja       0x261b1
0x26119: mov      dx, 0x3c4
0x2611D: mov      al, r8b
0x26120: out      dx, al
0x26121: mov      dx, 0x3c5
0x26125: in       al, dx
0x26126: mov      bl, al
0x26128: movzx    ecx, byte ptr [r14]
0x2612C: mov      dword ptr [rsp + 0xa0], ecx
0x26133: mov      edx, dword ptr [rsp + 0x94]
0x2613A: add      edx, ecx
0x2613C: mov      dword ptr [rsp + 0x94], edx
0x26143: cmp      ecx, edx
0x26145: jae      0x26176
0x26147: mov      dx, 0x3c4
0x2614B: mov      al, cl
0x2614D: out      dx, al
0x2614E: mov      dx, 0x3c5
0x26152: in       al, dx
0x26153: mov      byte ptr [r14], al
0x26156: add      r14, 1
0x2615A: mov      qword ptr [rsp + 0x148], r14
0x26162: add      rcx, 1
0x26166: mov      dword ptr [rsp + 0xa0], ecx
0x2616D: mov      edx, dword ptr [rsp + 0x94]
0x26174: jmp      0x26143
0x26176: mov      dx, 0x3c4
0x2617A: mov      al, r8b
0x2617D: out      dx, al
0x2617E: mov      dx, 0x3c5
0x26182: mov      al, bl
0x26184: out      dx, al
0x26185: sub      r14d, edi
0x26188: mov      eax, r14d
0x2618B: mov      qword ptr [r15 + 0x38], rax
0x2618F: mov      dword ptr [rsp + 0x90], esi
0x26196: jmp      0x261b1
0x26198: mov      dword ptr [rsp + 0x90], eax
0x2619F: xor      esi, esi
0x261A1: mov      r12, qword ptr [rsp + 0xe0]
0x261A9: mov      r15, qword ptr [rsp + 0xe8]
0x261B1: jmp      0x28e31
0x261B6: cmp      r13d, 0x7f
0x261BA: jbe      0x2625f
0x261C0: cmp      r10, rsi
0x261C3: je       0x2625f
0x261C9: mov      rcx, qword ptr [r10 + 8]
0x261CD: mov      qword ptr [rsp + 0xa8], rcx
0x261D5: cmp      rcx, rsi
0x261D8: je       0x2625f
0x261DE: lea      r9, [rsp + 0x140]
0x261E6: mov      edx, 1
0x261EB: mov      r8d, 0x80000000
0x261F1: call     qword ptr [rip - 0x1105f]  ; → IoOpenDeviceRegistryKey
0x261F7: mov      dword ptr [rsp + 0x90], eax
0x261FE: cmp      eax, esi
0x26200: jl       0x28e31
0x26206: lea      rax, [rsp + 0x98]
0x2620E: mov      qword ptr [rsp + 0x20], rax
0x26213: mov      r9d, dword ptr [rsp + 0x94]
0x2621B: mov      r8, qword ptr [rsp + 0xd0]
0x26223: mov      edx, 1
0x26228: mov      rcx, qword ptr [rsp + 0x140]
0x26230: call     qword ptr [rip - 0x1103e]  ; → ZwQueryKey
0x26236: mov      dword ptr [rsp + 0x90], eax
0x2623D: cmp      eax, esi
0x2623F: jl       0x2624c
0x26241: mov      eax, dword ptr [rsp + 0x98]
0x26248: mov      qword ptr [r15 + 0x38], rax
0x2624C: mov      rcx, qword ptr [rsp + 0x140]
0x26254: call     qword ptr [rip - 0x11122]  ; → ZwClose
0x2625A: jmp      0x28e31
0x2625F: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x2626A: jmp      0x28e31
0x2626F: or       cx, 0xffff
0x26274: call     qword ptr [r12 + 0x120]
0x2627C: mov      dword ptr [rsp + 0x9c], eax
0x26283: mov      r8d, eax
0x26286: shl      r8d, 4
0x2628A: add      r8d, 0x18
0x2628E: mov      dword ptr [rsp + 0x98], r8d
0x26296: cmp      dword ptr [rsp + 0x94], r8d
0x2629E: jb       0x28e31
0x262A4: lea      rcx, [r15 + 0x30]
0x262A8: mov      qword ptr [rsp + 0x20], rcx
0x262AD: mov      r9d, eax
0x262B0: mov      rdx, r14
0x262B3: mov      rcx, r12
0x262B6: call     0x1272c
0x262BB: mov      dword ptr [rsp + 0x90], eax
0x262C2: jmp      0x28e31
0x262C7: cmp      r13d, 0x7f
0x262CB: jbe      0x2631b
0x262CD: cmp      r10, rsi
0x262D0: je       0x2631b
0x262D2: mov      rax, qword ptr [r10 + 8]
0x262D6: mov      qword ptr [rsp + 0xa8], rax
0x262DE: cmp      rax, rsi
0x262E1: je       0x2631b
0x262E3: lea      rdx, [rsp + 0x98]
0x262EB: mov      qword ptr [rsp + 0x20], rdx
0x262F0: mov      r9, rcx
0x262F3: mov      r8d, r13d
0x262F6: mov      edx, 0xb
0x262FB: mov      rcx, rax
0x262FE: call     qword ptr [rip - 0x1112c]  ; → IoGetDeviceProperty
0x26304: mov      dword ptr [rsp + 0x90], eax
0x2630B: mov      eax, dword ptr [rsp + 0x98]
0x26312: mov      qword ptr [r15 + 0x38], rax
0x26316: jmp      0x28e31
0x2631B: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x26326: jmp      0x28e31
0x2632B: cmp      r13d, 0x7f
0x2632F: jbe      0x2637f
0x26331: cmp      r10, rsi
0x26334: je       0x2637f
0x26336: mov      rax, qword ptr [r10 + 8]
0x2633A: mov      qword ptr [rsp + 0xa8], rax
0x26342: cmp      rax, rsi
0x26345: je       0x2637f
0x26347: lea      rdx, [rsp + 0x98]
0x2634F: mov      qword ptr [rsp + 0x20], rdx
0x26354: mov      r9, rcx
0x26357: mov      r8d, r13d
0x2635A: mov      edx, 0xa
0x2635F: mov      rcx, rax
0x26362: call     qword ptr [rip - 0x11190]  ; → IoGetDeviceProperty
0x26368: mov      dword ptr [rsp + 0x90], eax
0x2636F: mov      eax, dword ptr [rsp + 0x98]
0x26376: mov      qword ptr [r15 + 0x38], rax
0x2637A: jmp      0x28e31
0x2637F: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x2638A: jmp      0x28e31
0x2638F: cmp      ebx, 1
0x26392: jb       0x263f1
0x26394: cmp      ebx, r13d
0x26397: ja       0x263f1
0x26399: cmp      r13d, eax
0x2639C: ja       0x263f1
0x2639E: lea      rcx, [r14 + rbx]
0x263A2: cmp      r14, rcx
0x263A5: jae      0x263c5
0x263A7: mov      dx, 0xcd0
0x263AB: mov      al, byte ptr [r14]
0x263AE: out      dx, al
0x263AF: mov      dx, 0xcd1
0x263B3: in       al, dx
0x263B4: mov      byte ptr [r14], al
0x263B7: add      r14, 1
0x263BB: mov      qword ptr [rsp + 0x148], r14
0x263C3: jmp      0x263a2
0x263C5: sub      r14d, edi
0x263C8: mov      eax, r14d
0x263CB: mov      qword ptr [r15 + 0x38], rax
0x263CF: mov      dword ptr [rsp + 0x90], esi
0x263D6: jmp      0x263f1
0x263D8: mov      dword ptr [rsp + 0x90], eax
0x263DF: xor      esi, esi
0x263E1: mov      r12, qword ptr [rsp + 0xe0]
0x263E9: mov      r15, qword ptr [rsp + 0xe8]
0x263F1: jmp      0x28e31
0x263F6: mov      eax, edx
0x263F8: sub      eax, 0x1d0
0x263FD: je       0x26511
0x26403: sub      eax, 4
0x26406: je       0x264e3
0x2640C: sub      eax, 4
0x2640F: je       0x264b5
0x26415: sub      eax, 4
0x26418: je       0x26484
0x2641A: sub      eax, 4
0x2641D: je       0x26456
0x2641F: cmp      eax, 4
0x26422: jne      0x28372
0x26428: cmp      ebx, 0x70
0x2642B: jb       0x28e31
0x26431: cmp      r13d, 0x70
0x26435: jb       0x28e31
0x2643B: lea      r8, [r15 + 0x30]
0x2643F: mov      rdx, r14
0x26442: mov      rcx, r12
0x26445: call     0x2d62c
0x2644A: mov      dword ptr [rsp + 0x90], eax
0x26451: jmp      0x28e31
0x26456: cmp      ebx, 0x28
0x26459: jb       0x28e31
0x2645F: cmp      r13d, 0x28
0x26463: jb       0x28e31
0x26469: lea      r8, [r15 + 0x30]
0x2646D: mov      rdx, r14
0x26470: mov      rcx, r12
0x26473: call     0x2cd68
0x26478: mov      dword ptr [rsp + 0x90], eax
0x2647F: jmp      0x28e31
0x26484: mov      eax, 0x40
0x26489: cmp      ebx, eax
0x2648B: jb       0x28e31
0x26491: cmp      r13d, eax
0x26494: jb       0x28e31
0x2649A: lea      r8, [r15 + 0x30]
0x2649E: mov      rdx, r14
0x264A1: mov      rcx, r12
0x264A4: call     0x2d964
0x264A9: mov      dword ptr [rsp + 0x90], eax
0x264B0: jmp      0x28e31
0x264B5: cmp      ebx, 0x28
0x264B8: jb       0x28e31
0x264BE: cmp      r13d, 0x28
0x264C2: jb       0x28e31
0x264C8: lea      r8, [r15 + 0x30]
0x264CC: mov      rdx, r14
0x264CF: mov      rcx, r12
0x264D2: call     0x2cc08
0x264D7: mov      dword ptr [rsp + 0x90], eax
0x264DE: jmp      0x28e31
0x264E3: cmp      ebx, 0x28
0x264E6: jb       0x28e31
0x264EC: cmp      r13d, 0x28
0x264F0: jb       0x28e31
0x264F6: lea      r8, [r15 + 0x30]
0x264FA: mov      rdx, r14
0x264FD: mov      rcx, r12
0x26500: call     0x2ca0c
0x26505: mov      dword ptr [rsp + 0x90], eax
0x2650C: jmp      0x28e31
0x26511: cmp      ebx, 0x28
0x26514: jb       0x28e31
0x2651A: cmp      r13d, 0x28
0x2651E: jb       0x28e31
0x26524: lea      r8, [r15 + 0x30]
0x26528: mov      rdx, r14
0x2652B: mov      rcx, r12
0x2652E: call     0x2c588
0x26533: mov      dword ptr [rsp + 0x90], eax
0x2653A: jmp      0x28e31
0x2653F: mov      eax, 0x90
0x26544: cmp      ebx, eax
0x26546: jb       0x28e31
0x2654C: mov      eax, 0x80
0x26551: cmp      r13d, eax
0x26554: jb       0x28e31
0x2655A: lea      r9, [r15 + 0x30]
0x2655E: mov      r8, r14
0x26561: mov      rdx, r14
0x26564: mov      rcx, r12
0x26567: call     0x2c464
0x2656C: mov      dword ptr [rsp + 0x90], eax
0x26573: jmp      0x28e31
0x26578: mov      eax, 0x41018
0x2657D: cmp      edx, eax
0x2657F: ja       0x27650
0x26585: cmp      edx, eax
0x26587: je       0x275a7
0x2658D: mov      eax, 0x40124
0x26592: cmp      edx, eax
0x26594: ja       0x26e74
0x2659A: cmp      edx, eax
0x2659C: je       0x26e13
0x265A2: mov      eax, edx
0x265A4: sub      eax, 0x1f0
0x265A9: je       0x26d3a
0x265AF: sub      eax, 4
0x265B2: je       0x26c77
0x265B8: sub      eax, 4
0x265BB: je       0x266ee
0x265C1: sub      eax, 0x3ff10
0x265C6: je       0x2667e
0x265CC: sub      eax, 4
0x265CF: je       0x2665d
0x265D5: cmp      eax, 0x14  ← IOCTL 0x14 (PhysMem_Map)
0x265D8: jne      0x28372
0x265DE: lea      edi, [rax + 0x4c]
0x265E1: cmp      r13d, edi
0x265E4: jb       0x28e31
0x265EA: mov      rbx, qword ptr [r15 + 0x18]
0x265EE: mov      r8d, r13d
0x265F1: xor      edx, edx
0x265F3: mov      rcx, rbx
0x265F6: call     0x13580
0x265FB: mov      dword ptr [rbx], 0x1000060
0x26601: mov      eax, dword ptr [r12]
0x26605: mov      dword ptr [rbx + 4], eax
0x26608: mov      eax, dword ptr [r12 + 4]
0x2660D: mov      dword ptr [rbx + 8], eax
0x26610: mov      eax, dword ptr [r12 + 8]
0x26615: mov      dword ptr [rbx + 0xc], eax
0x26618: lea      rcx, [rbx + 0x20]
0x2661C: mov      qword ptr [rsp + 0x148], rcx
0x26624: add      rbx, 0x5f
0x26628: lea      rdx, [rip + 0x17dc1]  ; → L"慊⁮㐱㈠㈰‶瑡〠㨸㘱㐺‸圠䭄㘠〰⸱㠱〰0쳌쳌쳌쳌剉彐䩍䍟乏剔䱏†┠㌰⁘†漠潦┠⁰漠硦┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠㐭⁵ⴠ┠㠰╘ੳ찀䥓䑖楲敶⁲䜠慵摲䄠敲⁡潃牲灵楴湯†瑓牡⁴〥㘱㙉場†楌業⁴〥㘱㙉場
쳌쳌쳌쳌쳌쳌쳌楳彫敧彴慴杲瑥⤨††††摡⁯瀥†摰⁸瀥†潉畂汩卤"
0x2662F: sub      rdx, rcx
0x26632: cmp      rcx, rbx
0x26635: jae      0x26645
0x26637: mov      al, byte ptr [rdx + rcx]
0x2663A: mov      byte ptr [rcx], al
0x2663C: add      rcx, 1
0x26640: cmp      al, sil
0x26643: jne      0x26632
0x26645: mov      qword ptr [rsp + 0x148], rcx
0x2664D: mov      qword ptr [r15 + 0x38], rdi
0x26651: mov      dword ptr [rsp + 0x90], esi
0x26658: jmp      0x28e31
0x2665D: mov      eax, esi
0x2665F: xchg     dword ptr [r12 + 0x64], eax
0x26664: neg      eax
0x26666: lock xadd dword ptr [r12 + 0x5c], eax
0x2666D: mov      dword ptr [r12 + 0x60], esi
0x26672: mov      dword ptr [rsp + 0x90], esi
0x26679: jmp      0x28e31
0x2667E: cmp      r13d, 0x34
0x26682: jb       0x28e31
0x26688: mov      rbx, qword ptr [r15 + 0x18]
0x2668C: mov      r8d, r13d
0x2668F: xor      edx, edx
0x26691: mov      rcx, rbx
0x26694: call     0x13580
0x26699: mov      dword ptr [rbx], 0x1000034
0x2669F: mov      dword ptr [rbx + 4], 0x44465f45
0x266A6: mov      dword ptr [rbx + 8], 3
0x266AD: mov      eax, dword ptr [r12 + 0x5c]
0x266B2: mov      dword ptr [rbx + 0x1c], eax
0x266B5: mov      eax, dword ptr [r12 + 0x60]
0x266BA: mov      dword ptr [rbx + 0x20], eax
0x266BD: mov      dword ptr [rbx + 0x24], esi
0x266C0: mov      dword ptr [rbx + 0x28], esi
0x266C3: mov      dword ptr [rbx + 0x2c], esi
0x266C6: mov      eax, dword ptr [r12 + 0x64]
0x266CB: mov      dword ptr [rbx + 0x30], eax
0x266CE: mov      dword ptr [rbx + 0xc], esi
0x266D1: mov      dword ptr [rbx + 0x10], esi
0x266D4: mov      dword ptr [rbx + 0x14], esi
0x266D7: mov      dword ptr [rbx + 0x18], esi
0x266DA: mov      qword ptr [r15 + 0x38], 0x34
0x266E2: mov      dword ptr [rsp + 0x90], esi
0x266E9: jmp      0x28e31
0x266EE: mov      r9d, 0x18
0x266F4: mov      dword ptr [rsp + 0x98], r9d
0x266FC: test     bl, 3
0x266FF: jne      0x26c2e
0x26705: cmp      ebx, 4
0x26708: jb       0x26c2e
0x2670E: cmp      ebx, r13d
0x26711: jne      0x26c2e
0x26717: mov      dword ptr [rsp + 0x90], esi
0x2671E: lea      rax, [r14 + rbx]
0x26722: mov      qword ptr [rsp + 0x150], rax
0x2672A: cmp      r14, rax
0x2672D: jae      0x26c20
0x26733: movzx    r8d, byte ptr [rdi]
0x26737: mov      eax, dword ptr [rdi]
0x26739: shr      eax, 8
0x2673C: movzx    edx, ax
0x2673F: mov      dword ptr [rsp + 0x28], r9d
0x26744: mov      dword ptr [rsp + 0x20], esi
0x26748: lea      r9, [rsp + 0x160]
0x26750: mov      rcx, r12
0x26753: call     0x119c8
0x26758: mov      r11d, eax
0x2675B: mov      dword ptr [rsp + 0x9c], eax
0x26762: mov      r10d, dword ptr [rsp + 0x98]
0x2676A: cmp      eax, r10d
0x2676D: jne      0x26bb7
0x26773: movzx    r8d, word ptr [rsp + 0x160]
0x2677C: cmp      r8w, 0x1022
0x26782: jne      0x267d2
0x26784: movzx    ebx, word ptr [rsp + 0x162]
0x2678C: cmp      bx, 0x43f4
0x26791: jne      0x267da
0x26793: movzx    r8d, byte ptr [rdi]
0x26797: mov      eax, dword ptr [rdi]
0x26799: shr      eax, 8
0x2679C: movzx    edx, ax
0x2679F: mov      dword ptr [rsp + 0x28], 4
0x267A7: mov      dword ptr [rsp + 0x20], 0x150
0x267AF: mov      r9, rdi
0x267B2: mov      rcx, r12
0x267B5: call     0x119c8
0x267BA: mov      r11d, eax
0x267BD: mov      dword ptr [rsp + 0x9c], eax
0x267C4: cmp      eax, 4
0x267C7: jne      0x2697b
0x267CD: jmp      0x26954
0x267D2: mov      bx, word ptr [rsp + 0x162]
0x267DA: cmp      r8w, 0x1022
0x267E0: jne      0x26b2c
0x267E6: cmp      bx, 0x43f7
0x267EB: jne      0x26b2c
0x267F1: mov      r10d, dword ptr [rsp + 0x170]
0x267F9: mov      dword ptr [rsp + 0xa0], r10d
0x26801: mov      dword ptr [rsp + 0xd8], r10d
0x26809: mov      eax, r10d
0x2680C: and      eax, 0xfffff000
0x26811: mov      dword ptr [rsp + 0xb8], eax
0x26818: mov      r11d, dword ptr [rsp + 0x174]
0x26820: mov      dword ptr [rsp + 0xd0], r11d
0x26828: mov      dword ptr [rsp + 0xbc], r11d
0x26830: mov      eax, r10d
0x26833: and      eax, 0xff7
0x26838: cmp      eax, 4
0x2683B: jne      0x26a9b
0x26841: mov      rbx, qword ptr [rsp + 0xb8]
0x26849: cmp      rbx, rsi
0x2684C: je       0x26aa3
0x26852: lea      r9d, [rax - 3]
0x26856: mov      r8d, 0x4000
0x2685C: mov      rdx, rbx
0x2685F: mov      rcx, r12
0x26862: call     0x29a50
0x26867: mov      r13, rax
0x2686A: mov      qword ptr [rsp + 0x100], rax
0x26872: cmp      rax, rsi
0x26875: je       0x269f5
0x2687B: cmp      word ptr [rsp + 0x160], 0x1022
0x26885: jne      0x268a2
0x26887: mov      r8d, 0x1e520
0x2688D: mov      rdx, rax
0x26890: mov      rcx, r12
0x26893: call     0x1180c
0x26898: movzx    edx, al
0x2689B: mov      dword ptr [rdi], edx
0x2689D: jmp      0x26943
0x268A2: mov      dword ptr [rsp + 0x90], 0xc0000002
0x268AD: bt       dword ptr [r12], 0x1f
0x268B3: jae      0x26943
0x268B9: mov      edx, dword ptr [rdi]
0x268BB: mov      ecx, 0xc0000002
0x268C0: call     0x12acc
0x268C5: movzx    r8d, word ptr [rsp + 0x162]
0x268CE: movzx    r10d, word ptr [rsp + 0x160]
0x268D7: mov      r11d, edx
0x268DA: shr      r11d, 5
0x268DE: and      r11d, 7
0x268E2: mov      ecx, edx
0x268E4: and      ecx, 0x1f
0x268E7: shr      edx, 8
0x268EA: movzx    r9d, dx
0x268EE: mov      qword ptr [rsp + 0x68], rax
0x268F3: mov      dword ptr [rsp + 0x60], 0xc0000002
0x268FB: mov      qword ptr [rsp + 0x58], r13
0x26900: mov      qword ptr [rsp + 0x50], rbx
0x26905: mov      eax, dword ptr [rsp + 0xa0]
0x2690C: mov      dword ptr [rsp + 0x48], eax
0x26910: mov      eax, dword ptr [rsp + 0xd0]
0x26917: mov      dword ptr [rsp + 0x40], eax
0x2691B: mov      dword ptr [rsp + 0x38], r8d
0x26920: mov      dword ptr [rsp + 0x30], r10d
0x26925: mov      dword ptr [rsp + 0x28], r11d
0x2692A: mov      dword ptr [rsp + 0x20], ecx
0x2692E: lea      r8, [rip + 0x1668b]  ; → L"佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸┠㄰䤲㐶⁘洠扢┠⁰猠獴┠㠰╘ੳ찀쳌佉呃彌䥓彖䵓䝂呅††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭〥場†敬⁮〥場⠠甥਩찀쳌쳌쳌쳌쳌佉呃彌䥓彖䵓䝂呅††††景⁯瀥†畢⁳甥†汳⁶〥堲"
0x26935: mov      edx, 2
0x2693A: lea      ecx, [rdx + 0x4b]
0x2693D: call     qword ptr [rip - 0x11763]  ; → DbgPrintEx
0x26943: mov      r8d, 0x4000
0x26949: mov      rdx, r13
0x2694C: mov      rcx, r12
0x2694F: call     0x29c2c
0x26954: add      rdi, 4
0x26958: mov      qword ptr [rsp + 0x138], rdi
0x26960: cmp      rdi, qword ptr [rsp + 0x150]
0x26968: jae      0x26c20
0x2696E: mov      r9d, dword ptr [rsp + 0x98]
0x26976: jmp      0x26733
0x2697B: mov      r8d, 0xc000009a
0x26981: mov      dword ptr [rsp + 0x90], r8d
0x26989: bt       dword ptr [r12], 0x1f
0x2698F: jae      0x26c20
0x26995: mov      edx, dword ptr [rdi]
0x26997: mov      ecx, r8d
0x2699A: call     0x12acc
0x2699F: mov      ebx, edx
0x269A1: shr      ebx, 5
0x269A4: and      ebx, 7
0x269A7: mov      ecx, edx
0x269A9: and      ecx, 0x1f
0x269AC: shr      edx, 8
0x269AF: movzx    r9d, dx
0x269B3: mov      qword ptr [rsp + 0x50], rax
0x269B8: mov      dword ptr [rsp + 0x48], r8d
0x269BD: mov      dword ptr [rsp + 0x40], r11d
0x269C2: mov      qword ptr [rsp + 0x38], 4
0x269CB: mov      dword ptr [rsp + 0x30], 0x150
0x269D3: mov      dword ptr [rsp + 0x28], ebx
0x269D7: mov      dword ptr [rsp + 0x20], ecx
0x269DB: lea      r8, [rip + 0x164be]  ; → L"佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝䀠〠╸㐰⁘┠⁵㴡┠⁵猠獴┠㠰╘ੳ찀쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸†瑳⁳〥堸猥
쳌쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸┠"
0x269E2: mov      edx, 2
0x269E7: lea      ecx, [rdx + 0x4b]
0x269EA: call     qword ptr [rip - 0x11810]  ; → DbgPrintEx
0x269F0: jmp      0x26c20
0x269F5: mov      dword ptr [rsp + 0x90], 0xc00000e6
0x26A00: bt       dword ptr [r12], 0x1f
0x26A06: jae      0x26c20
0x26A0C: mov      edx, dword ptr [rdi]
0x26A0E: mov      ecx, 0xc00000e6
0x26A13: call     0x12acc
0x26A18: movzx    r10d, word ptr [rsp + 0x162]
0x26A21: movzx    r11d, word ptr [rsp + 0x160]
0x26A2A: mov      r8d, edx
0x26A2D: shr      r8d, 5
0x26A31: and      r8d, 7
0x26A35: mov      ecx, edx
0x26A37: and      ecx, 0x1f
0x26A3A: shr      edx, 8
0x26A3D: movzx    r9d, dx
0x26A41: mov      qword ptr [rsp + 0x68], rax
0x26A46: mov      dword ptr [rsp + 0x60], 0xc00000e6
0x26A4E: mov      qword ptr [rsp + 0x58], r13
0x26A53: mov      qword ptr [rsp + 0x50], rbx
0x26A58: mov      eax, dword ptr [rsp + 0xa0]
0x26A5F: mov      dword ptr [rsp + 0x48], eax
0x26A63: mov      eax, dword ptr [rsp + 0xd0]
0x26A6A: mov      dword ptr [rsp + 0x40], eax
0x26A6E: mov      dword ptr [rsp + 0x38], r10d
0x26A73: mov      dword ptr [rsp + 0x30], r11d
0x26A78: mov      dword ptr [rsp + 0x28], r8d
0x26A7D: mov      dword ptr [rsp + 0x20], ecx
0x26A81: lea      r8, [rip + 0x16538]  ; → L"佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸┠㄰䤲㐶⁘洠扢┠⁰猠獴┠㠰╘ੳ찀쳌佉呃彌䥓彖䵓䝂呅††††景⁯瀥†畢⁳甥†汳⁶〥堲†浣⁤〥堲†畮⁭〥場†敬⁮〥場⠠甥਩찀쳌쳌쳌쳌쳌佉呃彌䥓彖䵓䝂呅††††景⁯瀥†畢⁳甥†汳⁶〥堲"
0x26A88: mov      edx, 2
0x26A8D: lea      ecx, [rdx + 0x4b]
0x26A90: call     qword ptr [rip - 0x118b6]  ; → DbgPrintEx
0x26A96: jmp      0x26c20
0x26A9B: mov      rbx, qword ptr [rsp + 0xb8]
0x26AA3: mov      dword ptr [rsp + 0x90], 0xc0000015
0x26AAE: bt       dword ptr [r12], 0x1f
0x26AB4: jae      0x26c20
0x26ABA: mov      edx, dword ptr [rdi]
0x26ABC: mov      ecx, 0xc0000015
0x26AC1: call     0x12acc
0x26AC6: mov      r8d, edx
0x26AC9: shr      r8d, 5
0x26ACD: and      r8d, 7
0x26AD1: mov      ecx, edx
0x26AD3: and      ecx, 0x1f
0x26AD6: shr      edx, 8
0x26AD9: movzx    r9d, dx
0x26ADD: mov      qword ptr [rsp + 0x60], rax
0x26AE2: mov      dword ptr [rsp + 0x58], 0xc0000015
0x26AEA: mov      qword ptr [rsp + 0x50], rbx
0x26AEF: mov      dword ptr [rsp + 0x48], r10d
0x26AF4: mov      dword ptr [rsp + 0x40], r11d
0x26AF9: mov      dword ptr [rsp + 0x38], 0x43f7
0x26B01: mov      dword ptr [rsp + 0x30], 0x1022
0x26B09: mov      dword ptr [rsp + 0x28], r8d
0x26B0E: mov      dword ptr [rsp + 0x20], ecx
0x26B12: lea      r8, [rip + 0x16437]  ; → L"佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸┠㄰䤲㐶⁘猠獴┠㠰╘ੳ찀쳌쳌쳌쳌쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸┠㄰䤲㐶⁘洠扢┠⁰猠獴┠㠰╘ੳ찀쳌佉呃彌䥓彖䵓䝂呅††††景⁯瀥†"
0x26B19: mov      edx, 2
0x26B1E: lea      ecx, [rdx + 0x4b]
0x26B21: call     qword ptr [rip - 0x11947]  ; → DbgPrintEx
0x26B27: jmp      0x26c20
0x26B2C: mov      r11d, 0xc000009d
0x26B32: mov      dword ptr [rsp + 0x90], r11d
0x26B3A: bt       dword ptr [r12], 0x1f
0x26B40: jae      0x26c20
0x26B46: mov      edx, dword ptr [rdi]
0x26B48: mov      ecx, r11d
0x26B4B: call     0x12acc
0x26B50: movzx    ebx, bx
0x26B53: movzx    r8d, r8w
0x26B57: mov      r10d, edx
0x26B5A: shr      r10d, 5
0x26B5E: and      r10d, 7
0x26B62: mov      ecx, edx
0x26B64: and      ecx, 0x1f
0x26B67: shr      edx, 8
0x26B6A: movzx    r9d, dx
0x26B6E: mov      qword ptr [rsp + 0x58], rax
0x26B73: mov      dword ptr [rsp + 0x50], r11d
0x26B78: mov      eax, dword ptr [rsp + 0x170]
0x26B7F: mov      dword ptr [rsp + 0x48], eax
0x26B83: mov      eax, dword ptr [rsp + 0x174]
0x26B8A: mov      dword ptr [rsp + 0x40], eax
0x26B8E: mov      dword ptr [rsp + 0x38], ebx
0x26B92: mov      dword ptr [rsp + 0x30], r8d
0x26B97: mov      dword ptr [rsp + 0x28], r10d
0x26B9C: mov      dword ptr [rsp + 0x20], ecx
0x26BA0: lea      r8, [rip + 0x16349]  ; → L"佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸†瑳⁳〥堸猥
쳌쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸┠㄰䤲㐶⁘猠獴┠㠰╘ੳ찀쳌쳌쳌쳌쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩"
0x26BA7: mov      edx, 2
0x26BAC: lea      ecx, [rdx + 0x4b]
0x26BAF: call     qword ptr [rip - 0x119d5]  ; → DbgPrintEx
0x26BB5: jmp      0x26c20
0x26BB7: mov      r8d, 0xc000009a
0x26BBD: mov      dword ptr [rsp + 0x90], r8d
0x26BC5: bt       dword ptr [r12], 0x1f
0x26BCB: jae      0x26c20
0x26BCD: mov      edx, dword ptr [rdi]
0x26BCF: mov      ecx, r8d
0x26BD2: call     0x12acc
0x26BD7: mov      ebx, edx
0x26BD9: shr      ebx, 5
0x26BDC: and      ebx, 7
0x26BDF: mov      ecx, edx
0x26BE1: and      ecx, 0x1f
0x26BE4: shr      edx, 8
0x26BE7: movzx    r9d, dx
0x26BEB: mov      qword ptr [rsp + 0x50], rax
0x26BF0: mov      dword ptr [rsp + 0x48], r8d
0x26BF5: mov      dword ptr [rsp + 0x40], r11d
0x26BFA: mov      dword ptr [rsp + 0x38], r10d
0x26BFF: mov      dword ptr [rsp + 0x30], esi
0x26C03: mov      dword ptr [rsp + 0x28], ebx
0x26C07: mov      dword ptr [rsp + 0x20], ecx
0x26C0B: lea      r8, [rip + 0x1628e]  ; → L"佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝䀠〠╸㐰⁘┠⁵㴡┠⁵猠獴┠㠰╘ੳ찀쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸†瑳⁳〥堸猥
쳌쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸┠"
0x26C12: mov      edx, 2
0x26C17: lea      ecx, [rdx + 0x4b]
0x26C1A: call     qword ptr [rip - 0x11a40]  ; → DbgPrintEx
0x26C20: sub      edi, r14d
0x26C23: mov      eax, edi
0x26C25: mov      qword ptr [r15 + 0x38], rax
0x26C29: jmp      0x28e31
0x26C2E: bt       dword ptr [r12], 0x1f
0x26C34: jae      0x28e31
0x26C3A: mov      edx, 0xc0000004
0x26C3F: mov      ecx, edx
0x26C41: call     0x12acc
0x26C46: mov      qword ptr [rsp + 0x40], rax
0x26C4B: mov      dword ptr [rsp + 0x38], edx
0x26C4F: mov      dword ptr [rsp + 0x30], r13d
0x26C54: mov      dword ptr [rsp + 0x28], ebx
0x26C58: mov      qword ptr [rsp + 0x20], r9
0x26C5D: lea      r8, [rip + 0x161dc]  ; → L"佉呃彌䥓彖䵁彄䍐敉†††灶⁷甥㸠眠扤┠Ⱶ戠摡椠汰┠㈰⁘牯℠‽灯⁬〥堲†瑳⁳〥堸猥
쳌쳌쳌쳌쳌쳌쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝䀠〠╸㐰⁘┠⁵㴡┠⁵猠獴┠㠰╘ੳ찀쳌佉呃彌䥓彖䵁彄䍐敉†††⁛㌥⁵‭〥甲ⴠ┠⁵⁝瘠摩┠㐰⁘搠摩┠㐰⁘戠牡┠㠰彘〥堸†"
0x26C64: mov      edx, 2
0x26C69: mov      ecx, r11d
0x26C6C: call     qword ptr [rip - 0x11a92]  ; → DbgPrintEx
0x26C72: jmp      0x28e31
0x26C77: cmp      ebx, 4
0x26C7A: jne      0x28e31
0x26C80: cmp      r13d, ebx
0x26C83: jne      0x28e31
0x26C89: mov      eax, dword ptr [r12 + 0x104]
0x26C91: cmp      eax, esi
0x26C93: je       0x26c9d
0x26C95: mov      dword ptr [r14], eax
0x26C98: jmp      0x26d26
0x26C9D: mov      eax, dword ptr [r14]
0x26CA0: mov      dword ptr [r12 + 0x104], eax
0x26CA8: cmp      eax, esi
0x26CAA: je       0x26d0e
0x26CAC: mov      qword ptr [rsp + 0xf8], 0xffffffffff76abc0
0x26CB8: mov      dword ptr [r12 + 0x100], 0x369e99
0x26CC4: movzx    edx, word ptr [r12 + 0x104]
0x26CCD: in       eax, dx
0x26CCE: mov      dword ptr [r12 + 0x108], eax
0x26CD6: xor      ecx, ecx
0x26CD8: call     qword ptr [r12 + 0x110]
0x26CE0: mov      dword ptr [r12 + 0x10c], eax
0x26CE8: lea      r9, [r12 + 0xc0]
0x26CF0: lea      rcx, [r12 + 0x80]
0x26CF8: mov      r8d, 0xfa0
0x26CFE: mov      rdx, qword ptr [rsp + 0xf8]
0x26D06: call     qword ptr [rip - 0x11c1c]  ; → KeSetTimerEx
0x26D0C: jmp      0x26d26
0x26D0E: lea      rcx, [r12 + 0x80]
0x26D16: call     qword ptr [rip - 0x11b5c]  ; → KeCancelTimer
0x26D1C: mov      edx, dword ptr [r12 + 0x4c]
0x26D21: mov      dword ptr [r12 + 0x50], edx
0x26D26: mov      qword ptr [r15 + 0x38], 4
0x26D2E: mov      dword ptr [rsp + 0x90], esi
0x26D35: jmp      0x28e31
0x26D3A: cmp      ebx, 8  ← IOCTL 0x08 (RDMSR)
0x26D3D: jb       0x28e31
0x26D43: test     bl, 3
0x26D46: jne      0x28e31
0x26D4C: cmp      r13d, 0xc  ← IOCTL 0x0C (WRMSR)
0x26D50: jb       0x28e31
0x26D56: test     r13b, 3
0x26D5A: jne      0x28e31
0x26D60: mov      r9d, dword ptr [r12 + 0x11ac]
0x26D68: mov      r8d, dword ptr [r14 + 4]
0x26D6C: mov      edx, dword ptr [r14]
0x26D6F: mov      rcx, r12
0x26D72: call     0x29944
0x26D77: mov      rbx, rax
0x26D7A: mov      qword ptr [rsp + 0x100], rax
0x26D82: cmp      rax, rsi
0x26D85: je       0x26e03
0x26D87: mov      edx, dword ptr [rax + 0x1e8]
0x26D8D: mov      dword ptr [rsp + 0xb0], edx
0x26D94: mov      ecx, edx
0x26D96: and      ecx, 0xfffff831
0x26D9C: or       ecx, 0x31
0x26D9F: mov      dword ptr [rax + 0x1e8], ecx
0x26DA5: mov      eax, dword ptr [rax + 0x1ec]
0x26DAB: mov      dword ptr [r14 + 8], eax
0x26DAF: mov      eax, dword ptr [rbx + 0x1e8]
0x26DB5: and      eax, 0xfffff830
0x26DBA: or       eax, 0x30
0x26DBD: mov      dword ptr [rbx + 0x1e8], eax
0x26DC3: mov      eax, dword ptr [rbx + 0x1ec]
0x26DC9: mov      dword ptr [r14 + 4], eax
0x26DCD: mov      eax, dword ptr [rbx + 0x1e8]
0x26DD3: mov      dword ptr [r14], eax
0x26DD6: mov      dword ptr [rbx + 0x1e8], edx
0x26DDC: mov      r8d, dword ptr [r12 + 0x11ac]
0x26DE4: mov      rdx, rbx
0x26DE7: mov      rcx, r12
0x26DEA: call     0x29c2c
0x26DEF: mov      qword ptr [r15 + 0x38], 0xc
0x26DF7: mov      dword ptr [rsp + 0x90], esi
0x26DFE: jmp      0x28e31
0x26E03: mov      dword ptr [rsp + 0x90], 0xc00000e6
0x26E0E: jmp      0x28e31
0x26E13: mov      eax, 0x40
0x26E18: cmp      r13d, eax
0x26E1B: jb       0x28e31
0x26E21: mov      rbx, qword ptr [r15 + 0x18]
0x26E25: mov      r8d, r13d
0x26E28: xor      edx, edx
0x26E2A: mov      rcx, rbx
0x26E2D: call     0x13580
0x26E32: mov      dword ptr [rbx], 4
0x26E38: mov      dword ptr [rbx + 4], 0x123
0x26E3F: mov      dword ptr [rbx + 8], 0x20121301
0x26E46: mov      r13d, 0x10
0x26E4C: mov      dword ptr [rbx + 0xc], r13d
0x26E50: mov      dword ptr [rbx + 0x10], 1
0x26E57: mov      dword ptr [rbx + 0x14], esi
0x26E5A: mov      dword ptr [rbx + 0x18], esi
0x26E5D: mov      eax, dword ptr [rsp + 0x94]
0x26E64: mov      qword ptr [r15 + 0x38], rax
0x26E68: mov      dword ptr [rsp + 0x90], esi
0x26E6F: jmp      0x28e31
0x26E74: mov      eax, edx
0x26E76: sub      eax, 0x40128
0x26E7B: je       0x2751e
0x26E81: mov      ecx, 0x18
0x26E86: sub      eax, ecx
0x26E88: je       0x274f0
0x26E8E: sub      eax, r8d
0x26E91: je       0x27235
0x26E97: sub      eax, r8d
0x26E9A: je       0x27196
0x26EA0: sub      eax, 4
0x26EA3: je       0x26f70
0x26EA9: cmp      eax, 0xea8
0x26EAE: jne      0x28372
0x26EB4: cmp      r10, rsi
0x26EB7: je       0x28e31
0x26EBD: mov      r8, qword ptr [r10 + 0x18]
0x26EC1: mov      qword ptr [rsp + 0xa8], r8
0x26EC9: cmp      r8, rsi
0x26ECC: je       0x28e31
0x26ED2: lea      rax, [r15 + 0x30]
0x26ED6: mov      qword ptr [rsp + 0x48], rax
0x26EDB: lea      rax, [rsp + 0xf8]
0x26EE3: mov      qword ptr [rsp + 0x40], rax
0x26EE8: mov      dword ptr [rsp + 0x38], r13d
0x26EED: mov      qword ptr [rsp + 0x30], r14
0x26EF2: mov      dword ptr [rsp + 0x28], ebx
0x26EF6: mov      qword ptr [rsp + 0x20], r14
0x26EFB: mov      r9d, 0x4100c
0x26F01: mov      rdx, r12
0x26F04: lea      rcx, [rip + 0x166f5]  ; → L"䕇彔义啑剉彙䅄䅔찀쳌쳌쳌쳌쳌쳌쳌䍓䥓䝟呅䥟兎䥕奒䑟呁⁁†景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䍓䥓偟十当䡔佒䝕⁈†††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䅐卓呟剈問䡇㈳찀䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌"
0x26F0B: call     0x3bf18
0x26F10: mov      dword ptr [rsp + 0x90], eax
0x26F17: cmp      eax, esi
0x26F19: jl       0x28e31
0x26F1F: bt       dword ptr [r12], 0xc
0x26F25: jae      0x28e31
0x26F2B: mov      rax, qword ptr [r15 + 0x38]
0x26F2F: mov      qword ptr [rsp + 0x30], rax
0x26F34: mov      rax, qword ptr [rsp + 0xa8]
0x26F3C: mov      qword ptr [rsp + 0x28], rax
0x26F41: mov      rdi, qword ptr [rsp + 0xc0]
0x26F49: mov      qword ptr [rsp + 0x20], rdi
0x26F4E: mov      r9, qword ptr [rsp + 0xb8]
0x26F56: lea      r8, [rip + 0x166c3]  ; → L"䍓䥓䝟呅䥟兎䥕奒䑟呁⁁†景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䍓䥓偟十当䡔佒䝕⁈†††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䅐卓呟剈問䡇㈳찀䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇㈳†††††景⁯瀥†"
0x26F5D: mov      edx, 2
0x26F62: lea      ecx, [rdx + 0x4b]
0x26F65: call     qword ptr [rip - 0x11d8b]  ; → DbgPrintEx
0x26F6B: jmp      0x28e31
0x26F70: cmp      ebx, r8d
0x26F73: jb       0x28e31
0x26F79: cmp      r13d, 4
0x26F7D: jb       0x28e31
0x26F83: mov      r9, qword ptr [r15 + 0x18]
0x26F87: mov      ebx, dword ptr [r9]
0x26F8A: mov      dword ptr [rsp + 0x9c], ebx
0x26F91: cmp      ebx, ecx
0x26F93: jae      0x27186
0x26F99: movzx    ecx, byte ptr [rbx + r12 + 0x2e70]
0x26FA2: mov      dword ptr [r14], ecx
0x26FA5: and      ecx, 0xc8
0x26FAB: mov      dword ptr [rsp + 0x98], ecx
0x26FB2: mov      al, byte ptr [r9 + 8]
0x26FB6: or       al, cl
0x26FB8: mov      byte ptr [rbx + r12 + 0x2e70], al
0x26FC0: mov      ecx, esi
0x26FC2: mov      dword ptr [rsp + 0x98], ecx
0x26FC9: mov      eax, ebx
0x26FCB: sub      eax, r8d
0x26FCE: je       0x2710d
0x26FD4: sub      eax, 1
0x26FD7: je       0x270e9
0x26FDD: sub      eax, 1
0x26FE0: je       0x270c6
0x26FE6: sub      eax, 1
0x26FE9: je       0x270a6
0x26FEF: sub      eax, 1
0x26FF2: je       0x2707f
0x26FF8: sub      eax, 1
0x26FFB: je       0x2705c
0x26FFD: sub      eax, 1
0x27000: je       0x27035
0x27002: cmp      eax, 1
0x27005: jne      0x27028
0x27007: lea      ebx, [rax + 7]
0x2700A: mov      dword ptr [rsp + 0x9c], ebx
0x27011: mov      dword ptr [rsp + 0x94], r8d
0x27019: lea      ecx, [rax + 0x7f]
0x2701C: mov      dword ptr [rsp + 0x98], ecx
0x27023: jmp      0x27133
0x27028: mov      r8d, dword ptr [rsp + 0x94]
0x27030: jmp      0x2712f
0x27035: mov      ebx, esi
0x27037: mov      dword ptr [rsp + 0x9c], ebx
0x2703E: mov      r8d, 8
0x27044: mov      dword ptr [rsp + 0x94], r8d
0x2704C: lea      ecx, [r8 + 0x78]
0x27050: mov      dword ptr [rsp + 0x98], ecx
0x27057: jmp      0x27133
0x2705C: mov      ebx, 8
0x27061: mov      dword ptr [rsp + 0x9c], ebx
0x27068: mov      dword ptr [rsp + 0x94], r8d
0x27070: lea      ecx, [rbx + 0x38]
0x27073: mov      dword ptr [rsp + 0x98], ecx
0x2707A: jmp      0x27133
0x2707F: mov      ebx, esi
0x27081: mov      dword ptr [rsp + 0x9c], ebx
0x27088: mov      r8d, 8
0x2708E: mov      dword ptr [rsp + 0x94], r8d
0x27096: lea      ecx, [r8 + 0x38]
0x2709A: mov      dword ptr [rsp + 0x98], ecx
0x270A1: jmp      0x27133
0x270A6: mov      ebx, 0xc
0x270AB: mov      dword ptr [rsp + 0x9c], ebx
0x270B2: mov      dword ptr [rsp + 0x94], r8d
0x270BA: lea      ecx, [rbx - 4]
0x270BD: mov      dword ptr [rsp + 0x98], ecx
0x270C4: jmp      0x27133
0x270C6: mov      ebx, 8
0x270CB: mov      dword ptr [rsp + 0x9c], ebx
0x270D2: lea      r8d, [rbx + 4]
0x270D6: mov      dword ptr [rsp + 0x94], r8d
0x270DE: mov      ecx, ebx
0x270E0: mov      dword ptr [rsp + 0x98], ebx
0x270E7: jmp      0x27133
0x270E9: mov      ebx, 4
0x270EE: mov      dword ptr [rsp + 0x9c], ebx
0x270F5: lea      r8d, [rbx + 4]
0x270F9: mov      dword ptr [rsp + 0x94], r8d
0x27101: mov      ecx, r8d
0x27104: mov      dword ptr [rsp + 0x98], ecx
0x2710B: jmp      0x27133
0x2710D: mov      ebx, esi
0x2710F: mov      dword ptr [rsp + 0x9c], ebx
0x27116: mov      r8d, 4
0x2711C: mov      dword ptr [rsp + 0x94], r8d
0x27124: lea      ecx, [r8 + 4]
0x27128: mov      dword ptr [rsp + 0x98], ecx
0x2712F: cmp      ecx, esi
0x27131: je       0x27172
0x27133: cmp      ebx, r8d
0x27136: jae      0x27172
0x27138: cmp      byte ptr [r9 + 8], sil
0x2713C: je       0x2714a
0x2713E: mov      eax, ebx
0x27140: or       byte ptr [rax + r12 + 0x2e70], cl
0x27148: jmp      0x27156
0x2714A: mov      eax, ebx
0x2714C: not      cl
0x2714E: and      byte ptr [rax + r12 + 0x2e70], cl
0x27156: add      ebx, 1
0x27159: cmp      ebx, dword ptr [rsp + 0x94]
0x27160: jae      0x2716b
0x27162: mov      ecx, dword ptr [rsp + 0x98]
0x27169: jmp      0x27138
0x2716B: mov      dword ptr [rsp + 0x9c], ebx
0x27172: mov      qword ptr [r15 + 0x38], 4
0x2717A: mov      dword ptr [rsp + 0x90], esi
0x27181: jmp      0x28e31
0x27186: mov      dword ptr [rsp + 0x90], 0xc0000015
0x27191: jmp      0x28e31
0x27196: bt       dword ptr [r12], 0x1c
0x2719C: jae      0x271e1
0x2719E: mov      dword ptr [rsp + 0x40], r13d
0x271A3: mov      dword ptr [rsp + 0x38], ebx
0x271A7: mov      qword ptr [rsp + 0x30], r14
0x271AC: mov      qword ptr [rsp + 0x28], r10
0x271B1: mov      qword ptr [rsp + 0x20], r9
0x271B6: mov      r9d, 0x58
0x271BC: lea      r8, [rip + 0x15a4d]  ; → L"剉彐䩍䍟乏剔䱏†┠㌰⁘†漠潦┠⁰漠硦┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠ੵ찀쳌쳌쳌쳌쳌쳌㕖㠮‵䈠極瑬䨠湡ㄠ‴〲㘲愠⁴㠰ㄺ㨶㠴†䑗⁋〶㄰ㄮ〸〰†V쳌쳌쳌쳌㕖㠮5쳌쳌쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†獭⁲〥堸†慶⁬〥堸╟㠰੘찀쳌쳌쳌佉呃彌䥓彖䑒卍⁒††††景⁯瀥†"
0x271C3: lea      edx, [r9 - 0x56]
0x271C7: mov      ecx, r11d
0x271CA: call     qword ptr [rip - 0x11ff0]  ; → DbgPrintEx
0x271D0: mov      r13d, dword ptr [rsp + 0x94]
0x271D8: mov      ecx, 0x18
0x271DD: lea      r8d, [rcx - 8]
0x271E1: cmp      ebx, r8d
0x271E4: jb       0x28e31
0x271EA: cmp      r13d, 4
0x271EE: jb       0x28e31
0x271F4: mov      rax, qword ptr [r15 + 0x18]
0x271F8: mov      edx, dword ptr [rax]
0x271FA: mov      dword ptr [rsp + 0x9c], edx
0x27201: cmp      edx, ecx
0x27203: jae      0x27225
0x27205: movzx    ecx, byte ptr [rdx + r12 + 0x2e70]
0x2720E: mov      dword ptr [r14], ecx
0x27211: mov      qword ptr [r15 + 0x38], 4
0x27219: mov      dword ptr [rsp + 0x90], esi
0x27220: jmp      0x28e31
0x27225: mov      dword ptr [rsp + 0x90], 0xc0000015
0x27230: jmp      0x28e31
0x27235: cmp      ebx, r8d
0x27238: jb       0x28e31
0x2723E: cmp      r13d, 4
0x27242: jb       0x28e31
0x27248: mov      rax, qword ptr [r15 + 0x18]
0x2724C: movsxd   r14, dword ptr [rax]
0x2724F: mov      dword ptr [rsp + 0xb0], r14d
0x27257: cmp      r13d, 0x10000
0x2725E: jne      0x27273
0x27260: cmp      r14d, esi
0x27263: jne      0x27273
0x27265: mov      ebx, 1
0x2726A: mov      dword ptr [rsp + 0xa0], ebx
0x27271: jmp      0x2727c
0x27273: mov      ebx, esi
0x27275: mov      dword ptr [rsp + 0xa0], ebx
0x2727C: mov      r8d, r13d
0x2727F: xor      edx, edx
0x27281: mov      rcx, rdi
0x27284: call     0x13580
0x27289: mov      rax, r14
0x2728C: mov      r10d, 0x5320
0x27292: cmp      r14d, r10d
0x27295: jne      0x272a9
0x27297: mov      r9d, 0x18
0x2729D: cmp      dword ptr [rsp + 0x94], r9d
0x272A5: jae      0x272b3
0x272A7: jmp      0x272af
0x272A9: mov      r9d, 0x18
0x272AF: cmp      ebx, esi
0x272B1: je       0x27304
0x272B3: mov      r8d, esi
0x272B6: sub      r10, rax
0x272B9: mov      r11, rsi
0x272BC: lea      r13, [r12 + 0x2e70]
0x272C4: mov      rax, r11
0x272C7: shr      rax, 3
0x272CB: lea      rbx, [r10 + rax*4]
0x272CF: mov      dl, byte ptr [r13]
0x272D3: and      edx, 1
0x272D6: mov      ecx, r8d
0x272D9: and      ecx, 7
0x272DC: shl      edx, cl
0x272DE: or       dword ptr [rbx + rdi], edx
0x272E1: add      r8d, 1
0x272E5: add      r11, 1
0x272E9: add      r13, 1
0x272ED: cmp      r8d, r9d
0x272F0: jb       0x272c4
0x272F2: mov      dword ptr [rsp + 0x9c], r8d
0x272FA: mov      ebx, dword ptr [rsp + 0xa0]
0x27301: mov      rax, r14
0x27304: cmp      r14d, 0xf200
0x2730B: jne      0x27317
0x2730D: cmp      dword ptr [rsp + 0x94], 8  ← IOCTL 0x08 (RDMSR)
0x27315: jae      0x2731b
0x27317: cmp      ebx, esi
0x27319: je       0x27354
0x2731B: mov      ecx, esi
0x2731D: mov      rdx, rdi
0x27320: sub      rdx, rax
0x27323: lea      r8, [r12 + 0x2e70]
0x2732B: mov      r13d, 0x10
0x27331: mov      al, byte ptr [r8]
0x27334: and      eax, 1
0x27337: shl      eax, cl
0x27339: or       dword ptr [rdx + 0xf204], eax
0x2733F: add      ecx, 1
0x27342: add      r8, 1
0x27346: cmp      ecx, r13d
0x27349: jb       0x27331
0x2734B: mov      dword ptr [rsp + 0x9c], ecx
0x27352: jmp      0x2735a
0x27354: mov      r13d, 0x10
0x2735A: cmp      r14d, 0xf300
0x27361: jne      0x2736d
0x27363: cmp      dword ptr [rsp + 0x94], 0x20
0x2736B: jae      0x27375
0x2736D: cmp      ebx, esi
0x2736F: je       0x274d9
0x27375: mov      ecx, esi
0x27377: mov      r9d, esi
0x2737A: mov      r10d, esi
0x2737D: lea      r11, [r12 + 0x2e70]
0x27385: mov      rbx, r11
0x27388: movzx    edx, byte ptr [rbx]
0x2738B: mov      dword ptr [rsp + 0x98], edx
0x27392: mov      eax, edx
0x27394: shr      eax, 1
0x27396: and      eax, 1
0x27399: shl      eax, cl
0x2739B: or       r10d, eax
0x2739E: shr      edx, 2
0x273A1: and      edx, 1
0x273A4: shl      edx, cl
0x273A6: or       r9d, edx
0x273A9: add      ecx, 1
0x273AC: add      rbx, 1
0x273B0: cmp      ecx, r13d
0x273B3: jb       0x27388
0x273B5: mov      r12d, esi
0x273B8: mov      r13d, esi
0x273BB: mov      r15d, esi
0x273BE: mov      r8d, 0x80
0x273C4: movzx    edx, byte ptr [r11]
0x273C8: mov      dword ptr [rsp + 0x98], edx
0x273CF: mov      ecx, r12d
0x273D2: mov      ebx, 2
0x273D7: shl      ebx, cl
0x273D9: mov      eax, edx
0x273DB: and      al, 8
0x273DD: neg      al
0x273DF: sbb      ecx, ecx
0x273E1: and      ecx, ebx
0x273E3: mov      eax, edx
0x273E5: and      eax, r8d
0x273E8: shl      eax, 8
0x273EB: or       ecx, eax
0x273ED: shr      edx, 6
0x273F0: and      edx, 1
0x273F3: or       ecx, edx
0x273F5: or       r15d, ecx
0x273F8: movzx    edx, byte ptr [r11 + 8]
0x273FD: mov      dword ptr [rsp + 0x98], edx
0x27404: mov      eax, edx
0x27406: and      al, 8
0x27408: neg      al
0x2740A: sbb      ecx, ecx
0x2740C: and      ecx, ebx
0x2740E: mov      eax, edx
0x27410: and      eax, r8d
0x27413: shl      eax, 8
0x27416: or       ecx, eax
0x27418: shr      edx, 6
0x2741B: and      edx, 1
0x2741E: or       ecx, edx
0x27420: or       r13d, ecx
0x27423: add      r12d, 1
0x27427: add      r11, 1
0x2742B: cmp      r12d, 8  ← IOCTL 0x08 (RDMSR)
0x2742F: jb       0x273c4
0x27431: mov      dword ptr [rsp + 0x9c], r12d
0x27439: mov      dword ptr [rsp + 0xa0], r15d
0x27441: movzx    ecx, r10b
0x27445: mov      eax, 0xf300
0x2744A: sub      eax, r14d
0x2744D: mov      dword ptr [rax + rdi], ecx
0x27450: shr      r10d, 8
0x27454: movzx    ecx, r10b
0x27458: mov      eax, 0xf308
0x2745D: sub      eax, r14d
0x27460: mov      dword ptr [rax + rdi], ecx
0x27463: movzx    ecx, r9b
0x27467: mov      eax, 0xf304
0x2746C: sub      eax, r14d
0x2746F: mov      dword ptr [rax + rdi], ecx
0x27472: shr      r9d, 8
0x27476: movzx    ecx, r9b
0x2747A: mov      eax, 0xf30c
0x2747F: sub      eax, r14d
0x27482: mov      dword ptr [rax + rdi], ecx
0x27485: mov      edx, r15d
0x27488: movzx    ecx, dl
0x2748B: mov      eax, 0xf310
0x27490: sub      eax, r14d
0x27493: mov      dword ptr [rax + rdi], ecx
0x27496: shr      edx, 8
0x27499: movzx    ecx, dl
0x2749C: mov      eax, 0xf314
0x274A1: sub      eax, r14d
0x274A4: mov      dword ptr [rax + rdi], ecx
0x274A7: movzx    ecx, r13b
0x274AB: mov      eax, 0xf318
0x274B0: sub      eax, r14d
0x274B3: mov      dword ptr [rax + rdi], ecx
0x274B6: shr      r13d, 8
0x274BA: movzx    ecx, r13b
0x274BE: mov      eax, 0xf31c
0x274C3: sub      eax, r14d
0x274C6: mov      dword ptr [rax + rdi], ecx
0x274C9: mov      r12, qword ptr [rsp + 0x128]
0x274D1: mov      r15, qword ptr [rsp + 0x120]
0x274D9: mov      eax, dword ptr [rsp + 0x94]
0x274E0: mov      qword ptr [r15 + 0x38], rax
0x274E4: mov      dword ptr [rsp + 0x90], esi
0x274EB: jmp      0x28e31
0x274F0: cmp      r13d, 4
0x274F4: jb       0x28e31
0x274FA: mov      r8d, r13d
0x274FD: xor      edx, edx
0x274FF: mov      rcx, r14
0x27502: call     0x13580
0x27507: mov      edx, dword ptr [rsp + 0x94]
0x2750E: mov      qword ptr [r15 + 0x38], rdx
0x27512: mov      dword ptr [rsp + 0x90], esi
0x27519: jmp      0x28e31
0x2751E: mov      dword ptr [rsp + 0x98], r8d
0x27526: mov      r8d, r13d
0x27529: cmp      r8, 0x700
0x27530: jb       0x28e31
0x27536: mov      r13, qword ptr [r15 + 0x18]
0x2753A: mov      ebx, 0x900
0x2753F: xor      edx, edx
0x27541: mov      rcx, r14
0x27544: call     0x13580
0x27549: mov      edx, esi
0x2754B: mov      dword ptr [rsp + 0x9c], edx
0x27552: cmp      dword ptr [rsp + 0x98], esi
0x27559: jbe      0x27591
0x2755B: lea      rcx, [r13 + 0x68]
0x2755F: mov      r13d, 0x10
0x27565: mov      dword ptr [rcx - 4], ebx
0x27568: lea      eax, [rbx + 0x100]
0x2756E: mov      dword ptr [rcx], eax
0x27570: mov      dword ptr [rcx - 0x1c], 1
0x27577: add      ebx, r13d
0x2757A: add      edx, 1
0x2757D: add      rcx, 0x70
0x27581: cmp      edx, dword ptr [rsp + 0x98]
0x27588: jb       0x27565
0x2758A: mov      dword ptr [rsp + 0x9c], edx
0x27591: mov      eax, edx
0x27593: imul     rax, rax, 0x70
0x27597: mov      qword ptr [r15 + 0x38], rax
0x2759B: mov      dword ptr [rsp + 0x90], esi
0x275A2: jmp      0x28e31
0x275A7: cmp      r13d, 8  ← IOCTL 0x08 (RDMSR)
0x275AB: jae      0x275ed
0x275AD: bt       dword ptr [r12], 0x1f
0x275B3: jae      0x275dd
0x275B5: mov      qword ptr [rsp + 0x30], 8
0x275BE: mov      dword ptr [rsp + 0x28], r13d
0x275C3: mov      qword ptr [rsp + 0x20], r10
0x275C8: lea      r8, [rip + 0x15ed1]  ; → L"佉呃彌䍓䥓䝟呅䅟䑄䕒卓†景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌呓剏䝁彅啑剅彙剐"
0x275CF: mov      edx, 2
0x275D4: mov      ecx, r11d
0x275D7: call     qword ptr [rip - 0x123fd]  ; → DbgPrintEx
0x275DD: mov      dword ptr [rsp + 0x90], 0xc0000023
0x275E8: jmp      0x28e31
0x275ED: cmp      r10, rsi
0x275F0: je       0x27640
0x275F2: mov      rax, qword ptr [r10 + 0x18]
0x275F6: mov      qword ptr [rsp + 0xa8], rax
0x275FE: cmp      rax, rsi
0x27601: je       0x27640
0x27603: mov      eax, dword ptr [r10 + 0x24]
0x27607: mov      dword ptr [rsp + 0x90], eax
0x2760E: cmp      eax, esi
0x27610: jl       0x28e31
0x27616: mov      dword ptr [rsp + 0x94], 8
0x27621: mov      eax, dword ptr [r10 + 0x28]
0x27625: mov      dword ptr [r14], eax
0x27628: mov      eax, dword ptr [r10 + 0x2c]
0x2762C: mov      dword ptr [r14 + 4], eax
0x27630: mov      eax, dword ptr [rsp + 0x94]
0x27637: mov      qword ptr [r15 + 0x38], rax
0x2763B: jmp      0x28e31
0x27640: mov      dword ptr [rsp + 0x90], 0xc0000010
0x2764B: jmp      0x28e31
0x27650: mov      ecx, 0x7c084
0x27655: cmp      edx, ecx
0x27657: ja       0x28334
0x2765D: cmp      edx, ecx
0x2765F: je       0x281e3
0x27665: mov      eax, edx
0x27667: sub      eax, 0x4d004
0x2766C: je       0x27e0d
0x27672: sub      eax, 4
0x27675: je       0x27d2d
0x2767B: sub      eax, 0x24
0x2767E: je       0x279a8
0x27684: sub      eax, 0x22fd4
0x27689: je       0x278ec
0x2768F: sub      eax, 0xa0
0x27694: je       0x27830
0x2769A: cmp      eax, 0x3fe0
0x2769F: jne      0x28372
0x276A5: mov      eax, 0x18
0x276AA: cmp      r13d, eax
0x276AD: jae      0x276e9
0x276AF: bt       dword ptr [r12], 0x1f
0x276B5: jae      0x276d9
0x276B7: mov      qword ptr [rsp + 0x30], rax
0x276BC: mov      dword ptr [rsp + 0x28], r13d
0x276C1: mov      qword ptr [rsp + 0x20], r10
0x276C6: lea      r8, [rip + 0x16213]  ; → L"䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌䍓䥓䥄䭓찀쳌쳌쳌䥍䥎佐呒卟䅍呒噟剅䥓乏찀쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉N쳌쳌쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†摡⁯瀥†敖獲潩⁮甥
쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†"
0x276CD: lea      edx, [rax - 0x16]
0x276D0: mov      ecx, r11d
0x276D3: call     qword ptr [rip - 0x124f9]  ; → DbgPrintEx
0x276D9: mov      dword ptr [rsp + 0x90], 0xc0000023
0x276E4: jmp      0x28e31
0x276E9: cmp      r10, rsi
0x276EC: je       0x28e31
0x276F2: mov      rcx, qword ptr [r10 + 8]
0x276F6: mov      qword ptr [rsp + 0x108], rcx
0x276FE: cmp      rcx, rsi
0x27701: je       0x28e31
0x27707: mov      r8, qword ptr [r10 + 0x18]
0x2770B: mov      qword ptr [rsp + 0xa8], r8
0x27713: cmp      r8, rsi
0x27716: je       0x28e31
0x2771C: test     byte ptr [r12 + 8], 1
0x27722: je       0x27793
0x27724: cmp      byte ptr [r10 + 0x2e], 0xff
0x27729: je       0x27793
0x2772B: lea      rax, [r15 + 0x30]
0x2772F: mov      rcx, qword ptr [rcx + 8]
0x27733: add      rcx, 0x38
0x27737: mov      qword ptr [rsp + 0x50], rax
0x2773C: mov      dword ptr [rsp + 0x48], r13d
0x27741: mov      dword ptr [rsp + 0x40], ebx
0x27745: mov      qword ptr [rsp + 0x38], r14
0x2774A: mov      qword ptr [rsp + 0x30], rcx
0x2774F: mov      qword ptr [rsp + 0x28], r8
0x27754: lea      rax, [rip + 0x161d5]  ; → L"䍓䥓䥄䭓찀쳌쳌쳌䥍䥎佐呒卟䅍呒噟剅䥓乏찀쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉N쳌쳌쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†摡⁯瀥†敖獲潩⁮甥
쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†"
0x2775B: mov      qword ptr [rsp + 0x20], rax
0x27760: mov      r9d, 0x1b0500
0x27766: mov      r8, r10
0x27769: mov      rdx, r12
0x2776C: lea      rcx, [rip + 0x161cd]  ; → L"䥍䥎佐呒卟䅍呒噟剅䥓乏찀쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉N쳌쳌쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†摡⁯瀥†敖獲潩⁮甥
쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†畯灴瑵戠"
0x27773: call     0x3c114
0x27778: mov      dword ptr [rsp + 0x90], eax
0x2777F: cmp      eax, esi
0x27781: jge      0x277e0
0x27783: mov      r8, qword ptr [rsp + 0xa8]
0x2778B: mov      r13d, dword ptr [rsp + 0x94]
0x27793: lea      rax, [r15 + 0x30]
0x27797: mov      qword ptr [rsp + 0x48], rax
0x2779C: lea      rax, [rsp + 0xf8]
0x277A4: mov      qword ptr [rsp + 0x40], rax
0x277A9: mov      dword ptr [rsp + 0x38], r13d
0x277AE: mov      qword ptr [rsp + 0x30], r14
0x277B3: mov      dword ptr [rsp + 0x28], ebx
0x277B7: mov      qword ptr [rsp + 0x20], r14
0x277BC: mov      r9d, 0x74080
0x277C2: mov      rdx, r12
0x277C5: lea      rcx, [rip + 0x16194]  ; → L"䵓剁彔䕇彔䕖卒佉N쳌쳌쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†摡⁯瀥†敖獲潩⁮甥
쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌"
0x277CC: call     0x3bf18
0x277D1: mov      dword ptr [rsp + 0x90], eax
0x277D8: cmp      eax, esi
0x277DA: jl       0x28e31
0x277E0: bt       dword ptr [r12], 0xc
0x277E6: jae      0x28e31
0x277EC: movzx    eax, byte ptr [r14]
0x277F0: mov      dword ptr [rsp + 0x30], eax
0x277F4: mov      rax, qword ptr [rsp + 0xa8]
0x277FC: mov      qword ptr [rsp + 0x28], rax
0x27801: mov      rdi, qword ptr [rsp + 0xc0]
0x27809: mov      qword ptr [rsp + 0x20], rdi
0x2780E: mov      r9, qword ptr [rsp + 0xb8]
0x27816: lea      r8, [rip + 0x16163]  ; → L"䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†摡⁯瀥†敖獲潩⁮甥
쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䵏䅍䑎찀쳌쳌쳌"
0x2781D: mov      edx, 2
0x27822: lea      ecx, [rdx + 0x4b]
0x27825: call     qword ptr [rip - 0x1264b]  ; → DbgPrintEx
0x2782B: jmp      0x28e31
0x27830: cmp      r10, rsi
0x27833: je       0x28e31
0x27839: mov      r8, qword ptr [r10 + 0x18]
0x2783D: mov      qword ptr [rsp + 0xa8], r8
0x27845: cmp      r8, rsi
0x27848: je       0x28e31
0x2784E: lea      rax, [r15 + 0x30]
0x27852: mov      qword ptr [rsp + 0x48], rax
0x27857: lea      rax, [rsp + 0xf8]
0x2785F: mov      qword ptr [rsp + 0x40], rax
0x27864: mov      dword ptr [rsp + 0x38], r13d
0x27869: mov      qword ptr [rsp + 0x30], r14
0x2786E: mov      dword ptr [rsp + 0x28], ebx
0x27872: mov      qword ptr [rsp + 0x20], r14
0x27877: mov      r9d, 0x700a0
0x2787D: mov      rdx, r12
0x27880: lea      rcx, [rip + 0x15f99]  ; → L"䕇彔剄噉彅䕇䵏呅奒䕟X쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟⁘†景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒찀쳌쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒†††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬"
0x27887: call     0x3bf18
0x2788C: mov      dword ptr [rsp + 0x90], eax
0x27893: cmp      eax, esi
0x27895: jl       0x28e31
0x2789B: bt       dword ptr [r12], 0xc
0x278A1: jae      0x28e31
0x278A7: mov      rax, qword ptr [r15 + 0x38]
0x278AB: mov      qword ptr [rsp + 0x30], rax
0x278B0: mov      rax, qword ptr [rsp + 0xa8]
0x278B8: mov      qword ptr [rsp + 0x28], rax
0x278BD: mov      rdi, qword ptr [rsp + 0xc0]
0x278C5: mov      qword ptr [rsp + 0x20], rdi
0x278CA: mov      r9, qword ptr [rsp + 0xb8]
0x278D2: lea      r8, [rip + 0x15f67]  ; → L"䕇彔剄噉彅䕇䵏呅奒䕟⁘†景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒찀쳌쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒†††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌䍓䥓䥄䭓찀쳌쳌쳌"
0x278D9: mov      edx, 2
0x278DE: lea      ecx, [rdx + 0x4b]
0x278E1: call     qword ptr [rip - 0x12707]  ; → DbgPrintEx
0x278E7: jmp      0x28e31
0x278EC: cmp      r10, rsi
0x278EF: je       0x28e31
0x278F5: mov      r8, qword ptr [r10 + 0x18]
0x278F9: mov      qword ptr [rsp + 0xa8], r8
0x27901: cmp      r8, rsi
0x27904: je       0x28e31
0x2790A: lea      rax, [r15 + 0x30]
0x2790E: mov      qword ptr [rsp + 0x48], rax
0x27913: lea      rax, [rsp + 0xf8]
0x2791B: mov      qword ptr [rsp + 0x40], rax
0x27920: mov      dword ptr [rsp + 0x38], r13d
0x27925: mov      qword ptr [rsp + 0x30], r14
0x2792A: mov      dword ptr [rsp + 0x28], ebx
0x2792E: mov      qword ptr [rsp + 0x20], r14
0x27933: mov      r9d, 0x70000
0x27939: mov      rdx, r12
0x2793C: lea      rcx, [rip + 0x15f3d]  ; → L"䕇彔剄噉彅䕇䵏呅奒찀쳌쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒†††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌䍓䥓䥄䭓찀쳌쳌쳌䥍䥎佐呒卟䅍呒噟剅䥓乏찀쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉N쳌쳌쳌쳌쳌쳌쳌"
0x27943: call     0x3bf18
0x27948: mov      dword ptr [rsp + 0x90], eax
0x2794F: cmp      eax, esi
0x27951: jl       0x28e31
0x27957: bt       dword ptr [r12], 0xc
0x2795D: jae      0x28e31
0x27963: mov      rax, qword ptr [r15 + 0x38]
0x27967: mov      qword ptr [rsp + 0x30], rax
0x2796C: mov      rax, qword ptr [rsp + 0xa8]
0x27974: mov      qword ptr [rsp + 0x28], rax
0x27979: mov      rdi, qword ptr [rsp + 0xc0]
0x27981: mov      qword ptr [rsp + 0x20], rdi
0x27986: mov      r9, qword ptr [rsp + 0xb8]
0x2798E: lea      r8, [rip + 0x15f0b]  ; → L"䕇彔剄噉彅䕇䵏呅奒†††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌䍓䥓䥄䭓찀쳌쳌쳌䥍䥎佐呒卟䅍呒噟剅䥓乏찀쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉N쳌쳌쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†"
0x27995: mov      edx, 2
0x2799A: lea      ecx, [rdx + 0x4b]
0x2799D: call     qword ptr [rip - 0x127c3]  ; → DbgPrintEx
0x279A3: jmp      0x28e31
0x279A8: cmp      ebx, 0x30
0x279AB: jae      0x279ec
0x279AD: bt       dword ptr [r12], 0x1f
0x279B3: jae      0x279dc
0x279B5: mov      qword ptr [rsp + 0x30], 0x30
0x279BE: mov      dword ptr [rsp + 0x28], ebx
0x279C2: mov      qword ptr [rsp + 0x20], r10
0x279C7: lea      r8, [rip + 0x15e02]  ; → L"呁彁䅐卓呟剈問䡇††††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟X쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟⁘†景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒찀쳌쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒†††景⁯瀥†景⁸瀥†摡⁯瀥†"
0x279CE: mov      edx, 2
0x279D3: mov      ecx, r11d
0x279D6: call     qword ptr [rip - 0x127fc]  ; → DbgPrintEx
0x279DC: mov      dword ptr [rsp + 0x90], 0xc0000023
0x279E7: jmp      0x28e31
0x279EC: cmp      r10, rsi
0x279EF: je       0x28e31
0x279F5: mov      rax, qword ptr [r10 + 0x18]
0x279F9: mov      qword ptr [rsp + 0xa8], rax
0x27A01: cmp      rax, rsi
0x27A04: je       0x28e31
0x27A0A: mov      rcx, r15
0x27A0D: call     qword ptr [rip - 0x12963]  ; → IoIs32bitProcess
0x27A13: cmp      al, sil
0x27A16: je       0x27c35
0x27A1C: mov      rdi, qword ptr [rsp + 0xc0]
0x27A24: lea      r13, [rdi + 0x90]
0x27A2B: mov      eax, dword ptr [r14 + 0x14]
0x27A2F: add      eax, dword ptr [r14 + 8]
0x27A33: mov      dword ptr [rsp + 0x98], eax
0x27A3A: cmp      eax, ebx
0x27A3C: ja       0x27c3d
0x27A42: mov      ecx, dword ptr [rsp + 0x94]
0x27A49: cmp      eax, ecx
0x27A4B: ja       0x27c44
0x27A51: cmp      eax, 0x230
0x27A56: ja       0x27c44
0x27A5C: mov      rax, qword ptr [r14 + 0x18]
0x27A60: mov      qword ptr [r13 + 0x20], rax
0x27A64: mov      rax, qword ptr [r14 + 0x20]
0x27A68: mov      qword ptr [r13 + 0x28], rax
0x27A6C: mov      eax, dword ptr [r14 + 0x14]
0x27A70: mov      r8d, dword ptr [r14 + 8]
0x27A74: lea      rdx, [rax + r14]
0x27A78: lea      rcx, [rax + r13]
0x27A7C: call     0x12e10
0x27A81: mov      word ptr [r13], 0x30
0x27A88: movzx    eax, word ptr [r14 + 2]
0x27A8D: mov      word ptr [r13 + 2], ax
0x27A92: mov      al, byte ptr [r14 + 4]
0x27A96: mov      byte ptr [r13 + 4], al
0x27A9A: mov      al, byte ptr [r14 + 5]
0x27A9E: mov      byte ptr [r13 + 5], al
0x27AA2: mov      al, byte ptr [r14 + 6]
0x27AA6: mov      byte ptr [r13 + 6], al
0x27AAA: mov      al, byte ptr [r14 + 7]
0x27AAE: mov      byte ptr [r13 + 7], al
0x27AB2: mov      eax, dword ptr [r14 + 8]
0x27AB6: mov      dword ptr [r13 + 8], eax
0x27ABA: mov      eax, dword ptr [r14 + 0xc]
0x27ABE: mov      dword ptr [r13 + 0xc], eax
0x27AC2: mov      eax, dword ptr [r14 + 0x10]
0x27AC6: mov      dword ptr [r13 + 0x10], eax
0x27ACA: mov      eax, dword ptr [r14 + 0x14]
0x27ACE: mov      qword ptr [r13 + 0x18], rax
0x27AD2: lea      rax, [r15 + 0x30]
0x27AD6: mov      qword ptr [rsp + 0x48], rax
0x27ADB: lea      rax, [rsp + 0xf8]
0x27AE3: mov      qword ptr [rsp + 0x40], rax
0x27AE8: mov      eax, dword ptr [rsp + 0x94]
0x27AEF: mov      dword ptr [rsp + 0x38], eax
0x27AF3: mov      qword ptr [rsp + 0x30], r13
0x27AF8: mov      dword ptr [rsp + 0x28], ebx
0x27AFC: mov      qword ptr [rsp + 0x20], r13
0x27B01: mov      r9d, 0x4d02c
0x27B07: mov      r8, qword ptr [rsp + 0xa8]
0x27B0F: mov      rdx, r12
0x27B12: lea      rcx, [rip + 0x15b97]  ; → L"䅐卓呟剈問䡇㈳찀䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌䅐卓呟剈問䡇찀쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇††††††景⁯瀥†"
0x27B19: call     0x3bf18
0x27B1E: mov      ecx, eax
0x27B20: mov      dword ptr [rsp + 0x90], eax
0x27B27: cmp      eax, esi
0x27B29: jl       0x27be7
0x27B2F: movzx    eax, word ptr [r13]
0x27B34: mov      word ptr [r14], ax
0x27B38: movzx    eax, word ptr [r13 + 2]
0x27B3D: mov      word ptr [r14 + 2], ax
0x27B42: mov      al, byte ptr [r13 + 4]
0x27B46: mov      byte ptr [r14 + 4], al
0x27B4A: mov      al, byte ptr [r13 + 5]
0x27B4E: mov      byte ptr [r14 + 5], al
0x27B52: mov      al, byte ptr [r13 + 6]
0x27B56: mov      byte ptr [r14 + 6], al
0x27B5A: mov      al, byte ptr [r13 + 7]
0x27B5E: mov      byte ptr [r14 + 7], al
0x27B62: mov      ecx, dword ptr [r13 + 8]
0x27B66: mov      dword ptr [r14 + 8], ecx
0x27B6A: mov      eax, dword ptr [r13 + 0xc]
0x27B6E: mov      dword ptr [r14 + 0xc], eax
0x27B72: mov      eax, dword ptr [r13 + 0x10]
0x27B76: mov      dword ptr [r14 + 0x10], eax
0x27B7A: mov      rax, qword ptr [r13 + 0x20]
0x27B7E: mov      qword ptr [r14 + 0x18], rax
0x27B82: mov      rax, qword ptr [r13 + 0x28]
0x27B86: mov      qword ptr [r14 + 0x20], rax
0x27B8A: mov      eax, dword ptr [r14 + 0x14]
0x27B8E: mov      r8, rcx
0x27B91: lea      rdx, [rax + r13]
0x27B95: lea      rcx, [rax + r14]
0x27B99: call     0x12e10
0x27B9E: bt       dword ptr [r12], 0xc
0x27BA4: jae      0x28e31
0x27BAA: mov      rax, qword ptr [r15 + 0x38]
0x27BAE: mov      qword ptr [rsp + 0x30], rax
0x27BB3: mov      rax, qword ptr [rsp + 0xa8]
0x27BBB: mov      qword ptr [rsp + 0x28], rax
0x27BC0: mov      qword ptr [rsp + 0x20], rdi
0x27BC5: mov      r9, qword ptr [rsp + 0xb8]
0x27BCD: lea      r8, [rip + 0x15aec]  ; → L"䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌䅐卓呟剈問䡇찀쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†"
0x27BD4: mov      edx, 2
0x27BD9: lea      ecx, [rdx + 0x4b]
0x27BDC: call     qword ptr [rip - 0x12a02]  ; → DbgPrintEx
0x27BE2: jmp      0x28e31
0x27BE7: bt       dword ptr [r12], 0xc
0x27BED: jae      0x28e31
0x27BF3: call     0x12acc
0x27BF8: mov      qword ptr [rsp + 0x38], rax
0x27BFD: mov      dword ptr [rsp + 0x30], ecx
0x27C01: mov      rax, qword ptr [rsp + 0xa8]
0x27C09: mov      qword ptr [rsp + 0x28], rax
0x27C0E: mov      qword ptr [rsp + 0x20], rdi
0x27C13: mov      r9, qword ptr [rsp + 0xb8]
0x27C1B: lea      r8, [rip + 0x15ade]  ; → L"䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌䅐卓呟剈問䡇찀쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌呁彁䅐卓呟剈問䡇††††景⁯瀥†景⁸瀥†湩異⁴畢"
0x27C22: mov      edx, 2
0x27C27: lea      ecx, [rdx + 0x4b]
0x27C2A: call     qword ptr [rip - 0x12a50]  ; → DbgPrintEx
0x27C30: jmp      0x28e31
0x27C35: mov      rdi, qword ptr [rsp + 0xc0]
0x27C3D: mov      ecx, dword ptr [rsp + 0x94]
0x27C44: lea      rax, [r15 + 0x30]
0x27C48: mov      qword ptr [rsp + 0x48], rax
0x27C4D: lea      rax, [rsp + 0xf8]
0x27C55: mov      qword ptr [rsp + 0x40], rax
0x27C5A: mov      dword ptr [rsp + 0x38], ecx
0x27C5E: mov      qword ptr [rsp + 0x30], r14
0x27C63: mov      dword ptr [rsp + 0x28], ebx
0x27C67: mov      qword ptr [rsp + 0x20], r14
0x27C6C: mov      r9d, 0x4d02c
0x27C72: mov      r8, qword ptr [rsp + 0xa8]
0x27C7A: mov      rdx, r12
0x27C7D: lea      rcx, [rip + 0x15abc]  ; → L"䅐卓呟剈問䡇찀쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌呁彁䅐卓呟剈問䡇††††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟X쳌쳌쳌쳌쳌"
0x27C84: call     0x3bf18
0x27C89: mov      ecx, eax
0x27C8B: mov      dword ptr [rsp + 0x90], eax
0x27C92: cmp      eax, esi
0x27C94: jl       0x27cdf
0x27C96: bt       dword ptr [r12], 0xc
0x27C9C: jae      0x28e31
0x27CA2: mov      rax, qword ptr [r15 + 0x38]
0x27CA6: mov      qword ptr [rsp + 0x30], rax
0x27CAB: mov      rax, qword ptr [rsp + 0xa8]
0x27CB3: mov      qword ptr [rsp + 0x28], rax
0x27CB8: mov      qword ptr [rsp + 0x20], rdi
0x27CBD: mov      r9, qword ptr [rsp + 0xb8]
0x27CC5: lea      r8, [rip + 0x15a84]  ; → L"䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌呁彁䅐卓呟剈問䡇††††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟X쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅"
0x27CCC: mov      edx, 2
0x27CD1: lea      ecx, [rdx + 0x4b]
0x27CD4: call     qword ptr [rip - 0x12afa]  ; → DbgPrintEx
0x27CDA: jmp      0x28e31
0x27CDF: bt       dword ptr [r12], 0xc
0x27CE5: jae      0x28e31
0x27CEB: call     0x12acc
0x27CF0: mov      qword ptr [rsp + 0x38], rax
0x27CF5: mov      dword ptr [rsp + 0x30], ecx
0x27CF9: mov      rax, qword ptr [rsp + 0xa8]
0x27D01: mov      qword ptr [rsp + 0x28], rax
0x27D06: mov      qword ptr [rsp + 0x20], rdi
0x27D0B: mov      r9, qword ptr [rsp + 0xb8]
0x27D13: lea      r8, [rip + 0x15a76]  ; → L"䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌呁彁䅐卓呟剈問䡇††††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟X쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟⁘†景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅"
0x27D1A: mov      edx, 2
0x27D1F: lea      ecx, [rdx + 0x4b]
0x27D22: call     qword ptr [rip - 0x12b48]  ; → DbgPrintEx
0x27D28: jmp      0x28e31
0x27D2D: cmp      r10, rsi
0x27D30: je       0x27dfd
0x27D36: mov      r8, qword ptr [r10 + 0x18]
0x27D3A: mov      qword ptr [rsp + 0xa8], r8
0x27D42: cmp      r8, rsi
0x27D45: je       0x27dfd
0x27D4B: lea      rax, [r15 + 0x30]
0x27D4F: mov      qword ptr [rsp + 0x48], rax
0x27D54: lea      rax, [rsp + 0xf8]
0x27D5C: mov      qword ptr [rsp + 0x40], rax
0x27D61: mov      dword ptr [rsp + 0x38], r13d
0x27D66: mov      qword ptr [rsp + 0x30], r14
0x27D6B: mov      dword ptr [rsp + 0x28], ebx
0x27D6F: mov      qword ptr [rsp + 0x20], r14
0x27D74: mov      r9d, 0x4d008
0x27D7A: mov      rdx, r12
0x27D7D: lea      rcx, [rip + 0x1569c]  ; → L"佉呃彌䍓䥓䵟义偉剏T쳌쳌쳌쳌쳌쳌佉呃彌䍓䥓䵟义偉剏⁔††景⁯瀥†景⁸瀥†摡⁯瀥†畢⁦瀥†灩⁬ⴥ甴†灯⁬ⴥ甴†敬⁮甥
쳌쳌쳌쳌쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓†景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†湩異⁴畢"
0x27D84: call     0x3bf18
0x27D89: mov      dword ptr [rsp + 0x90], eax
0x27D90: cmp      eax, esi
0x27D92: jl       0x28e31
0x27D98: bt       dword ptr [r12], 0xc
0x27D9E: jae      0x28e31
0x27DA4: mov      rax, qword ptr [r15 + 0x38]
0x27DA8: mov      qword ptr [rsp + 0x48], rax
0x27DAD: mov      eax, dword ptr [rsp + 0x94]
0x27DB4: mov      dword ptr [rsp + 0x40], eax
0x27DB8: mov      dword ptr [rsp + 0x38], ebx
0x27DBC: mov      qword ptr [rsp + 0x30], r14
0x27DC1: mov      rax, qword ptr [rsp + 0xa8]
0x27DC9: mov      qword ptr [rsp + 0x28], rax
0x27DCE: mov      rdi, qword ptr [rsp + 0xc0]
0x27DD6: mov      qword ptr [rsp + 0x20], rdi
0x27DDB: mov      r9, qword ptr [rsp + 0xb8]
0x27DE3: lea      r8, [rip + 0x15656]  ; → L"佉呃彌䍓䥓䵟义偉剏⁔††景⁯瀥†景⁸瀥†摡⁯瀥†畢⁦瀥†灩⁬ⴥ甴†灯⁬ⴥ甴†敬⁮甥
쳌쳌쳌쳌쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓†景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌"
0x27DEA: mov      edx, 2
0x27DEF: lea      ecx, [rdx + 0x4b]
0x27DF2: call     qword ptr [rip - 0x12c18]  ; → DbgPrintEx
0x27DF8: jmp      0x28e31
0x27DFD: mov      dword ptr [rsp + 0x90], 0xc0000010
0x27E08: jmp      0x28e31
0x27E0D: cmp      ebx, 0x38
0x27E10: jae      0x27e51
0x27E12: bt       dword ptr [r12], 0x1f
0x27E18: jae      0x27e41
0x27E1A: mov      qword ptr [rsp + 0x30], 0x38
0x27E23: mov      dword ptr [rsp + 0x28], ebx
0x27E27: mov      qword ptr [rsp + 0x20], r10
0x27E2C: lea      r8, [rip + 0x1582d]  ; → L"䍓䥓偟十当䡔佒䝕⁈†††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䅐卓呟剈問䡇㈳찀䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌䅐卓呟剈問䡇찀쳌䅐卓呟剈問䡇††"
0x27E33: mov      edx, 2
0x27E38: mov      ecx, r11d
0x27E3B: call     qword ptr [rip - 0x12c61]  ; → DbgPrintEx
0x27E41: mov      dword ptr [rsp + 0x90], 0xc0000023
0x27E4C: jmp      0x28e31
0x27E51: cmp      r10, rsi
0x27E54: je       0x28e31
0x27E5A: mov      rax, qword ptr [r10 + 0x18]
0x27E5E: mov      qword ptr [rsp + 0xa8], rax
0x27E66: cmp      rax, rsi
0x27E69: je       0x28e31
0x27E6F: mov      rcx, r15
0x27E72: call     qword ptr [rip - 0x12dc8]  ; → IoIs32bitProcess
0x27E78: cmp      al, sil
0x27E7B: je       0x280eb
0x27E81: mov      rdi, qword ptr [rsp + 0xc0]
0x27E89: lea      r13, [rdi + 0x90]
0x27E90: movzx    edx, byte ptr [r14 + 7]
0x27E95: add      edx, dword ptr [r14 + 0x18]
0x27E99: mov      r8d, dword ptr [r14 + 0xc]
0x27E9D: add      r8d, dword ptr [r14 + 0x14]
0x27EA1: cmp      edx, r8d
0x27EA4: cmova    r8d, edx
0x27EA8: mov      dword ptr [rsp + 0x98], r8d
0x27EB0: cmp      r8d, ebx
0x27EB3: ja       0x280f3
0x27EB9: mov      ecx, dword ptr [rsp + 0x94]
0x27EC0: cmp      r8d, ecx
0x27EC3: ja       0x280fa
0x27EC9: mov      eax, 0x260
0x27ECE: cmp      r8d, eax
0x27ED1: ja       0x280fa
0x27ED7: cmp      dword ptr [r14 + 0x18], 0x38
0x27EDC: jb       0x280fa
0x27EE2: movdqu   xmm0, xmmword ptr [r14 + 0x1c]
0x27EE8: movdqu   xmmword ptr [r13 + 0x24], xmm0
0x27EEE: mov      eax, dword ptr [r14 + 0x18]
0x27EF2: movzx    r8d, byte ptr [r14 + 7]
0x27EF7: lea      rdx, [rax + r14]
0x27EFB: lea      rcx, [r13 + rax]
0x27F00: call     0x12e10
0x27F05: mov      ecx, dword ptr [r14 + 0x14]
0x27F09: mov      r8d, dword ptr [r14 + 0xc]
0x27F0D: lea      rdx, [rcx + r14]
0x27F11: add      rcx, r13
0x27F14: call     0x12e10
0x27F19: mov      word ptr [r13], 0x38
0x27F20: mov      al, byte ptr [r14 + 2]
0x27F24: mov      byte ptr [r13 + 2], al
0x27F28: mov      al, byte ptr [r14 + 3]
0x27F2C: mov      byte ptr [r13 + 3], al
0x27F30: mov      al, byte ptr [r14 + 4]
0x27F34: mov      byte ptr [r13 + 4], al
0x27F38: mov      al, byte ptr [r14 + 5]
0x27F3C: mov      byte ptr [r13 + 5], al
0x27F40: mov      al, byte ptr [r14 + 6]
0x27F44: mov      byte ptr [r13 + 6], al
0x27F48: mov      al, byte ptr [r14 + 7]
0x27F4C: mov      byte ptr [r13 + 7], al
0x27F50: mov      al, byte ptr [r14 + 8]
0x27F54: mov      byte ptr [r13 + 8], al
0x27F58: mov      eax, dword ptr [r14 + 0xc]
0x27F5C: mov      dword ptr [r13 + 0xc], eax
0x27F60: mov      eax, dword ptr [r14 + 0x10]
0x27F64: mov      dword ptr [r13 + 0x10], eax
0x27F68: mov      eax, dword ptr [r14 + 0x14]
0x27F6C: mov      qword ptr [r13 + 0x18], rax
0x27F70: mov      eax, dword ptr [r14 + 0x18]
0x27F74: mov      dword ptr [r13 + 0x20], eax
0x27F78: lea      rax, [r15 + 0x30]
0x27F7C: mov      qword ptr [rsp + 0x48], rax
0x27F81: lea      rax, [rsp + 0xf8]
0x27F89: mov      qword ptr [rsp + 0x40], rax
0x27F8E: mov      eax, dword ptr [rsp + 0x94]
0x27F95: mov      dword ptr [rsp + 0x38], eax
0x27F99: mov      qword ptr [rsp + 0x30], r13
0x27F9E: mov      dword ptr [rsp + 0x28], ebx
0x27FA2: mov      qword ptr [rsp + 0x20], r13
0x27FA7: mov      r9d, 0x4d004
0x27FAD: mov      r8, qword ptr [rsp + 0xa8]
0x27FB5: mov      rdx, r12
0x27FB8: lea      rcx, [rip + 0x156f1]  ; → L"䅐卓呟剈問䡇㈳찀䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌䅐卓呟剈問䡇찀쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇††††††景⁯瀥†"
0x27FBF: call     0x3bf18
0x27FC4: mov      ecx, eax
0x27FC6: mov      dword ptr [rsp + 0x90], eax
0x27FCD: cmp      eax, esi
0x27FCF: jl       0x2809d
0x27FD5: mov      al, byte ptr [r13 + 2]
0x27FD9: mov      byte ptr [r14 + 2], al
0x27FDD: mov      al, byte ptr [r13 + 3]
0x27FE1: mov      byte ptr [r14 + 3], al
0x27FE5: mov      al, byte ptr [r13 + 4]
0x27FE9: mov      byte ptr [r14 + 4], al
0x27FED: mov      al, byte ptr [r13 + 5]
0x27FF1: mov      byte ptr [r14 + 5], al
0x27FF5: mov      al, byte ptr [r13 + 6]
0x27FF9: mov      byte ptr [r14 + 6], al
0x27FFD: movzx    ecx, byte ptr [r13 + 7]
0x28002: mov      byte ptr [r14 + 7], cl
0x28006: mov      al, byte ptr [r13 + 8]
0x2800A: mov      byte ptr [r14 + 8], al
0x2800E: mov      eax, dword ptr [r13 + 0xc]
0x28012: mov      dword ptr [r14 + 0xc], eax
0x28016: mov      eax, dword ptr [r13 + 0x10]
0x2801A: mov      dword ptr [r14 + 0x10], eax
0x2801E: movdqu   xmm0, xmmword ptr [r13 + 0x24]
0x28024: movdqu   xmmword ptr [r14 + 0x1c], xmm0
0x2802A: mov      eax, dword ptr [r14 + 0x18]
0x2802E: mov      r8, rcx
0x28031: lea      rdx, [r13 + rax]
0x28036: lea      rcx, [rax + r14]
0x2803A: call     0x12e10
0x2803F: mov      ecx, dword ptr [r14 + 0x14]
0x28043: mov      r8d, dword ptr [r14 + 0xc]
0x28047: lea      rdx, [r13 + rcx]
0x2804C: add      rcx, r14
0x2804F: call     0x12e10
0x28054: bt       dword ptr [r12], 0xc
0x2805A: jae      0x28e31
0x28060: mov      rax, qword ptr [r15 + 0x38]
0x28064: mov      qword ptr [rsp + 0x30], rax
0x28069: mov      rax, qword ptr [rsp + 0xa8]
0x28071: mov      qword ptr [rsp + 0x28], rax
0x28076: mov      qword ptr [rsp + 0x20], rdi
0x2807B: mov      r9, qword ptr [rsp + 0xb8]
0x28083: lea      r8, [rip + 0x15636]  ; → L"䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌䅐卓呟剈問䡇찀쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†"
0x2808A: mov      edx, 2
0x2808F: lea      ecx, [rdx + 0x4b]
0x28092: call     qword ptr [rip - 0x12eb8]  ; → DbgPrintEx
0x28098: jmp      0x28e31
0x2809D: bt       dword ptr [r12], 0xc
0x280A3: jae      0x28e31
0x280A9: call     0x12acc
0x280AE: mov      qword ptr [rsp + 0x38], rax
0x280B3: mov      dword ptr [rsp + 0x30], ecx
0x280B7: mov      rax, qword ptr [rsp + 0xa8]
0x280BF: mov      qword ptr [rsp + 0x28], rax
0x280C4: mov      qword ptr [rsp + 0x20], rdi
0x280C9: mov      r9, qword ptr [rsp + 0xb8]
0x280D1: lea      r8, [rip + 0x15628]  ; → L"䅐卓呟剈問䡇㈳†††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌䅐卓呟剈問䡇찀쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌呁彁䅐卓呟剈問䡇††††景⁯瀥†景⁸瀥†湩異⁴畢"
0x280D8: mov      edx, 2
0x280DD: lea      ecx, [rdx + 0x4b]
0x280E0: call     qword ptr [rip - 0x12f06]  ; → DbgPrintEx
0x280E6: jmp      0x28e31
0x280EB: mov      rdi, qword ptr [rsp + 0xc0]
0x280F3: mov      ecx, dword ptr [rsp + 0x94]
0x280FA: lea      rax, [r15 + 0x30]
0x280FE: mov      qword ptr [rsp + 0x48], rax
0x28103: lea      rax, [rsp + 0xf8]
0x2810B: mov      qword ptr [rsp + 0x40], rax
0x28110: mov      dword ptr [rsp + 0x38], ecx
0x28114: mov      qword ptr [rsp + 0x30], r14
0x28119: mov      dword ptr [rsp + 0x28], ebx
0x2811D: mov      qword ptr [rsp + 0x20], r14
0x28122: mov      r9d, 0x4d004
0x28128: mov      r8, qword ptr [rsp + 0xa8]
0x28130: mov      rdx, r12
0x28133: lea      rcx, [rip + 0x15606]  ; → L"䅐卓呟剈問䡇찀쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌呁彁䅐卓呟剈問䡇††††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟X쳌쳌쳌쳌쳌"
0x2813A: call     0x3bf18
0x2813F: mov      ecx, eax
0x28141: mov      dword ptr [rsp + 0x90], eax
0x28148: cmp      eax, esi
0x2814A: jl       0x28195
0x2814C: bt       dword ptr [r12], 0xc
0x28152: jae      0x28e31
0x28158: mov      rax, qword ptr [r15 + 0x38]
0x2815C: mov      qword ptr [rsp + 0x30], rax
0x28161: mov      rax, qword ptr [rsp + 0xa8]
0x28169: mov      qword ptr [rsp + 0x28], rax
0x2816E: mov      qword ptr [rsp + 0x20], rdi
0x28173: mov      r9, qword ptr [rsp + 0xb8]
0x2817B: lea      r8, [rip + 0x155ce]  ; → L"䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌呁彁䅐卓呟剈問䡇††††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟X쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅"
0x28182: mov      edx, 2
0x28187: lea      ecx, [rdx + 0x4b]
0x2818A: call     qword ptr [rip - 0x12fb0]  ; → DbgPrintEx
0x28190: jmp      0x28e31
0x28195: bt       dword ptr [r12], 0xc
0x2819B: jae      0x28e31
0x281A1: call     0x12acc
0x281A6: mov      qword ptr [rsp + 0x38], rax
0x281AB: mov      dword ptr [rsp + 0x30], ecx
0x281AF: mov      rax, qword ptr [rsp + 0xa8]
0x281B7: mov      qword ptr [rsp + 0x28], rax
0x281BC: mov      qword ptr [rsp + 0x20], rdi
0x281C1: mov      r9, qword ptr [rsp + 0xb8]
0x281C9: lea      r8, [rip + 0x155c0]  ; → L"䅐卓呟剈問䡇††††††景⁯瀥†景⁸瀥†摡⁯瀥†‭〥堸猥
쳌쳌쳌呁彁䅐卓呟剈問䡇††††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟X쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅奒䕟⁘†景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䕇彔剄噉彅䕇䵏呅"
0x281D0: mov      edx, 2
0x281D5: lea      ecx, [rdx + 0x4b]
0x281D8: call     qword ptr [rip - 0x12ffe]  ; → DbgPrintEx
0x281DE: jmp      0x28e31
0x281E3: cmp      ebx, 0x20
0x281E6: jae      0x28227
0x281E8: bt       dword ptr [r12], 0x1f
0x281EE: jae      0x28217
0x281F0: mov      qword ptr [rsp + 0x30], 0x20
0x281F9: mov      dword ptr [rsp + 0x28], ebx
0x281FD: mov      qword ptr [rsp + 0x20], r10
0x28202: lea      r8, [rip + 0x157b7]  ; → L"䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䵏䅍䑎찀쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†摡⁯瀥†畂晦牥匠穩⁥甥
"
0x28209: mov      edx, 2
0x2820E: mov      ecx, r11d
0x28211: call     qword ptr [rip - 0x13037]  ; → DbgPrintEx
0x28217: mov      dword ptr [rsp + 0x90], 0xc0000023
0x28222: jmp      0x28e31
0x28227: cmp      r13d, r8d
0x2822A: jae      0x28268
0x2822C: bt       dword ptr [r12], 0x1f
0x28232: jae      0x28258
0x28234: mov      qword ptr [rsp + 0x30], r8
0x28239: mov      dword ptr [rsp + 0x28], r13d
0x2823E: mov      qword ptr [rsp + 0x20], r10
0x28243: lea      r8, [rip + 0x157c6]  ; → L"䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䵏䅍䑎찀쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†摡⁯瀥†畂晦牥匠穩⁥甥
䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌"
0x2824A: mov      edx, 2
0x2824F: mov      ecx, r11d
0x28252: call     qword ptr [rip - 0x13078]  ; → DbgPrintEx
0x28258: mov      dword ptr [rsp + 0x90], 0xc0000023
0x28263: jmp      0x28e31
0x28268: cmp      r10, rsi
0x2826B: je       0x28e31
0x28271: mov      rax, qword ptr [r10 + 8]
0x28275: mov      qword ptr [rsp + 0x108], rax
0x2827D: cmp      rax, rsi
0x28280: je       0x28e31
0x28286: mov      r8, qword ptr [r10 + 0x18]
0x2828A: mov      qword ptr [rsp + 0xa8], r8
0x28292: cmp      r8, rsi
0x28295: je       0x28e31
0x2829B: lea      rax, [r15 + 0x30]
0x2829F: mov      qword ptr [rsp + 0x48], rax
0x282A4: lea      rax, [rsp + 0xf8]
0x282AC: mov      qword ptr [rsp + 0x40], rax
0x282B1: mov      dword ptr [rsp + 0x38], r13d
0x282B6: mov      qword ptr [rsp + 0x30], r14
0x282BB: mov      dword ptr [rsp + 0x28], ebx
0x282BF: mov      qword ptr [rsp + 0x20], r14
0x282C4: mov      r9d, ecx
0x282C7: mov      rdx, r12
0x282CA: lea      rcx, [rip + 0x1578f]  ; → L"䵓剁彔䕓䑎䑟䥒䕖䍟䵏䅍䑎찀쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†摡⁯瀥†畂晦牥匠穩⁥甥
䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌"
0x282D1: call     0x3bf18
0x282D6: mov      dword ptr [rsp + 0x90], eax
0x282DD: cmp      eax, esi
0x282DF: jl       0x28e31
0x282E5: bt       dword ptr [r12], 0xc
0x282EB: jae      0x28e31
0x282F1: mov      eax, dword ptr [r14]
0x282F4: mov      dword ptr [rsp + 0x30], eax
0x282F8: mov      rax, qword ptr [rsp + 0xa8]
0x28300: mov      qword ptr [rsp + 0x28], rax
0x28305: mov      rdi, qword ptr [rsp + 0xc0]
0x2830D: mov      qword ptr [rsp + 0x20], rdi
0x28312: mov      r9, qword ptr [rsp + 0xb8]
0x2831A: lea      r8, [rip + 0x1575f]  ; → L"䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†摡⁯瀥†畂晦牥匠穩⁥甥
䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌䥍䥎佐呒䥟䕄呎䙉Y쳌쳌쳌쳌쳌쳌쳌"
0x28321: mov      edx, 2
0x28326: lea      ecx, [rdx + 0x4b]
0x28329: call     qword ptr [rip - 0x1314f]  ; → DbgPrintEx
0x2832F: jmp      0x28e31
0x28334: mov      eax, edx
0x28336: sub      eax, 0x7c088
0x2833B: je       0x28aff
0x28341: sub      eax, 0x217ff8
0x28346: je       0x28a93
0x2834C: sub      eax, 0x100
0x28351: je       0x289f7
0x28357: sub      eax, 0x3d280
0x2835C: je       0x288a9
0x28362: sub      eax, 0x5ac04
0x28367: je       0x2866f
0x2836D: cmp      eax, 0x1c
0x28370: je       0x283da
0x28372: mov      dword ptr [rsp + 0x90], 0xc0000010
0x2837D: bt       dword ptr [r12], 0x1f
0x28383: jae      0x28e31
0x28389: mov      ecx, 0xc0000010
0x2838E: call     0x12acc
0x28393: shr      edx, 2
0x28396: and      edx, 0xfff
0x2839C: mov      qword ptr [rsp + 0x50], rax
0x283A1: mov      dword ptr [rsp + 0x48], ecx
0x283A5: mov      dword ptr [rsp + 0x40], r13d
0x283AA: mov      dword ptr [rsp + 0x38], ebx
0x283AE: mov      qword ptr [rsp + 0x30], r14
0x283B3: mov      qword ptr [rsp + 0x28], r10
0x283B8: mov      qword ptr [rsp + 0x20], r9
0x283BD: mov      r9d, edx
0x283C0: lea      r8, [rip + 0x16059]  ; → L"剉彐䩍䍟乏剔䱏†┠㌰⁘†漠潦┠⁰漠硦┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠㐭⁵ⴠ┠㠰╘ੳ찀䥓䑖楲敶⁲䜠慵摲䄠敲⁡潃牲灵楴湯†瑓牡⁴〥㘱㙉場†楌業⁴〥㘱㙉場
쳌쳌쳌쳌쳌쳌쳌楳彫敧彴慴杲瑥⤨††††摡⁯瀥†摰⁸瀥†潉畂汩卤湹档潲潮獵獆剤煥敵瑳  慦汩摥‬潮瀠潯੬찀쳌쳌쳌"
0x283C7: mov      edx, 2
0x283CC: mov      ecx, r11d
0x283CF: call     qword ptr [rip - 0x131f5]  ; → DbgPrintEx
0x283D5: jmp      0x28e31
0x283DA: mov      qword ptr [rsp + 0xf8], 0xffffffffffb3b4c0
0x283E6: lea      eax, [rbx - 0x10]
0x283E9: cmp      eax, 0x30
0x283EC: ja       0x28e31
0x283F2: cmp      r10, rsi
0x283F5: je       0x2865f
0x283FB: mov      rax, qword ptr [r10 + 0x10]
0x283FF: mov      qword ptr [rsp + 0xa8], rax
0x28407: cmp      rax, rsi
0x2840A: je       0x2865f
0x28410: mov      r8, rbx
0x28413: lea      rcx, [r10 + 0x90]
0x2841A: mov      rdx, r14
0x2841D: call     0x12e10
0x28422: mov      r10, qword ptr [rsp + 0xc0]
0x2842A: mov      rdx, qword ptr [r10 + 8]
0x2842E: mov      r8, qword ptr [rsp + 0xa8]
0x28436: cmp      rdx, r8
0x28439: cmove    rdx, rsi
0x2843D: mov      qword ptr [rsp + 0x108], rdx
0x28445: lea      r9, [rip + 0x14664]  ; → L"摩o쳌쳌쳌쳌쳌쳌摉o쳌쳌쳌쳌쳌쳌摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌"
0x2844C: mov      edi, dword ptr [rsp + 0xb0]
0x28453: cmp      r8, rsi
0x28456: je       0x28e31
0x2845C: bt       dword ptr [r12], 0x16
0x28462: jae      0x2857f
0x28468: mov      al, byte ptr [r10 + 0x9f]
0x2846F: cmp      al, 0x20
0x28471: jle      0x2847f
0x28473: movsx    ecx, al
0x28476: mov      dword ptr [rsp + 0xa0], ecx
0x2847D: jmp      0x2848a
0x2847F: mov      dword ptr [rsp + 0xa0], 0x20
0x2848A: mov      al, byte ptr [r10 + 0x9e]
0x28491: cmp      al, 0x20
0x28493: jle      0x284a1
0x28495: movsx    ecx, al
0x28498: mov      dword ptr [rsp + 0xd0], ecx
0x2849F: jmp      0x284ac
0x284A1: mov      dword ptr [rsp + 0xd0], 0x20
0x284AC: mov      al, byte ptr [r10 + 0x9d]
0x284B3: cmp      al, 0x20
0x284B5: jle      0x284bd
0x284B7: movsx    r13d, al
0x284BB: jmp      0x284c3
0x284BD: mov      r13d, 0x20
0x284C3: mov      al, byte ptr [r10 + 0x9c]
0x284CA: cmp      al, 0x20
0x284CC: jle      0x284d4
0x284CE: movsx    r11d, al
0x284D2: jmp      0x284da
0x284D4: mov      r11d, 0x20
0x284DA: lea      rdx, [r10 + 0x90]
0x284E1: lea      rcx, [rip + 0x145e8]  ; → L"摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌剉彐䩍䍟佌䕓††††††景⁯瀥†"
0x284E8: cmp      r8, qword ptr [r10 + 0x10]
0x284EC: cmove    rcx, r9
0x284F0: mov      eax, dword ptr [rsp + 0x94]
0x284F7: mov      dword ptr [rsp + 0x80], eax
0x284FE: mov      qword ptr [rsp + 0x78], r14
0x28503: mov      dword ptr [rsp + 0x70], ebx
0x28507: mov      qword ptr [rsp + 0x68], rdx
0x2850C: mov      qword ptr [rsp + 0x60], r8
0x28511: mov      qword ptr [rsp + 0x58], rcx
0x28516: mov      qword ptr [rsp + 0x50], r10
0x2851B: mov      rax, qword ptr [rsp + 0xb8]
0x28523: mov      qword ptr [rsp + 0x48], rax
0x28528: mov      eax, dword ptr [rsp + 0xa0]
0x2852F: mov      dword ptr [rsp + 0x40], eax
0x28533: mov      eax, dword ptr [rsp + 0xd0]
0x2853A: mov      dword ptr [rsp + 0x38], eax
0x2853E: mov      dword ptr [rsp + 0x30], r13d
0x28543: mov      dword ptr [rsp + 0x28], r11d
0x28548: mov      eax, dword ptr [r10 + 0x98]
0x2854F: mov      dword ptr [rsp + 0x20], eax
0x28553: mov      r9d, dword ptr [r10 + 0x94]
0x2855A: lea      r8, [rip + 0x15daf]  ; → L"䍁䥐䕟啎彍䡃䱉剄久┠㈰⁘┠⁵┠╣╣╣⁣漠潦┠⁰漠硦┠⁰┠⁳瀥†灩┠⁰ⴥ甲†灯┠⁰甥
쳌쳌쳌쳌쳌쳌䍁䥐䕟啎彍䡃䱉剄久찀쳌쳌쳌쳌쳌쳌䍁䥐䕟䅖彌䕍䡔䑏†㤸㄰찀쳌쳌쳌쳌ⴥ㈲㈮猲†景⁯瀥†景⁸瀥†猥┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠ੵ찀쳌쳌慊⁮㐱㈠㈰‶瑡〠㨸㘱㐺‸圠䭄㘠〰"
0x28561: mov      edx, 2
0x28566: lea      ecx, [rdx + 0x4b]
0x28569: call     qword ptr [rip - 0x1338f]  ; → DbgPrintEx
0x2856F: mov      r8, qword ptr [rsp + 0xa8]
0x28577: mov      r10, qword ptr [rsp + 0xc0]
0x2857F: lea      rax, [r15 + 0x30]
0x28583: lea      rcx, [r10 + 0x90]
0x2858A: mov      qword ptr [rsp + 0x48], rax
0x2858F: lea      rax, [rsp + 0xf8]
0x28597: mov      qword ptr [rsp + 0x40], rax
0x2859C: mov      eax, dword ptr [rsp + 0x94]
0x285A3: mov      dword ptr [rsp + 0x38], eax
0x285A7: mov      qword ptr [rsp + 0x30], r14
0x285AC: mov      dword ptr [rsp + 0x28], ebx
0x285B0: mov      qword ptr [rsp + 0x20], rcx
0x285B5: mov      r9d, edi
0x285B8: mov      rdx, r12
0x285BB: lea      rcx, [rip + 0x15dae]  ; → L"䍁䥐䕟啎彍䡃䱉剄久찀쳌쳌쳌쳌쳌쳌䍁䥐䕟䅖彌䕍䡔䑏†㤸㄰찀쳌쳌쳌쳌ⴥ㈲㈮猲†景⁯瀥†景⁸瀥†猥┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠ੵ찀쳌쳌慊⁮㐱㈠㈰‶瑡〠㨸㘱㐺‸圠䭄㘠〰⸱㠱〰0쳌쳌쳌쳌剉彐䩍䍟乏剔䱏†┠㌰⁘†漠潦┠⁰漠硦┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠㐭⁵ⴠ┠㠰╘ੳ찀"
0x285C2: call     0x3bf18
0x285C7: mov      r11d, eax
0x285CA: mov      dword ptr [rsp + 0x90], eax
0x285D1: mov      r10, qword ptr [rsp + 0xc0]
0x285D9: lea      r9, [rip + 0x144d0]  ; → L"摩o쳌쳌쳌쳌쳌쳌摉o쳌쳌쳌쳌쳌쳌摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌"
0x285E0: jmp      0x2862c
0x285E2: mov      r11d, eax
0x285E5: mov      dword ptr [rsp + 0x270], eax
0x285EC: mov      dword ptr [rsp + 0x90], eax
0x285F3: xor      esi, esi
0x285F5: lea      r9, [rip + 0x144b4]  ; → L"摩o쳌쳌쳌쳌쳌쳌摉o쳌쳌쳌쳌쳌쳌摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌"
0x285FC: mov      r12, qword ptr [rsp + 0xe0]
0x28604: mov      r10, qword ptr [rsp + 0xc0]
0x2860C: mov      r14, qword ptr [rsp + 0x178]
0x28614: mov      ebx, dword ptr [rsp + 0xd8]
0x2861B: mov      eax, dword ptr [rsp + 0xb0]
0x28622: mov      r15, qword ptr [rsp + 0xe8]
0x2862A: mov      edi, eax
0x2862C: cmp      r11d, 0xc0000022
0x28633: je       0x28642
0x28635: cmp      r11d, 0xc0000002
0x2863C: jne      0x28e31
0x28642: mov      r8, qword ptr [rsp + 0x108]
0x2864A: mov      qword ptr [rsp + 0xa8], r8
0x28652: mov      qword ptr [rsp + 0x108], rsi
0x2865A: jmp      0x28453
0x2865F: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x2866A: jmp      0x28e31
0x2866F: mov      qword ptr [rsp + 0xf8], 0xffffffffffb3b4c0
0x2867B: cmp      ebx, 8  ← IOCTL 0x08 (RDMSR)
0x2867E: jb       0x28e31
0x28684: cmp      r10, rsi
0x28687: je       0x28899
0x2868D: mov      rcx, qword ptr [r10 + 0x10]
0x28691: mov      qword ptr [rsp + 0x128], rcx
0x28699: mov      qword ptr [rsp + 0xa8], rcx
0x286A1: cmp      rcx, rsi
0x286A4: je       0x28899
0x286AA: mov      qword ptr [rsp + 0x150], r14
0x286B2: mov      rax, qword ptr [r10 + 8]
0x286B6: cmp      rax, rcx
0x286B9: cmove    rax, rsi
0x286BD: mov      qword ptr [rsp + 0x108], rax
0x286C5: mov      rdi, qword ptr [rsp + 0xc0]
0x286CD: cmp      rcx, rsi
0x286D0: je       0x28e31
0x286D6: lea      rcx, [rsp + 0x2f0]
0x286DE: lea      rdx, [rip + 0x15cab]  ; → L"䍁䥐䕟䅖彌䕍䡔䑏†㤸㄰찀쳌쳌쳌쳌ⴥ㈲㈮猲†景⁯瀥†景⁸瀥†猥┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠ੵ찀쳌쳌慊⁮㐱㈠㈰‶瑡〠㨸㘱㐺‸圠䭄㘠〰⸱㠱〰0쳌쳌쳌쳌剉彐䩍䍟乏剔䱏†┠㌰⁘†漠潦┠⁰漠硦┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠㐭⁵ⴠ┠㠰╘ੳ찀䥓䑖楲敶⁲䜠慵摲䄠敲⁡潃牲灵楴湯"
0x286E5: mov      r8d, 0x20
0x286EB: call     0x12e10
0x286F0: movzx    edx, byte ptr [r14 + 4]
0x286F5: mov      eax, 0x20
0x286FA: cmp      dl, al
0x286FC: cmova    eax, edx
0x286FF: mov      byte ptr [rsp + 0x302], al
0x28706: movzx    ecx, byte ptr [r14 + 5]
0x2870B: mov      eax, 0x20
0x28710: cmp      cl, al
0x28712: cmova    eax, ecx
0x28715: mov      byte ptr [rsp + 0x303], al
0x2871C: movzx    ecx, byte ptr [r14 + 6]
0x28721: mov      eax, 0x20
0x28726: cmp      cl, al
0x28728: cmova    eax, ecx
0x2872B: mov      byte ptr [rsp + 0x304], al
0x28732: movzx    ecx, byte ptr [r14 + 7]
0x28737: mov      eax, 0x20
0x2873C: cmp      cl, al
0x2873E: cmova    eax, ecx
0x28741: mov      byte ptr [rsp + 0x305], al
0x28748: bt       dword ptr [r12], 0x17
0x2874E: jae      0x287c7
0x28750: lea      rax, [rip + 0x14379]  ; → L"摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌剉彐䩍䍟佌䕓††††††景⁯瀥†"
0x28757: mov      r8, qword ptr [rsp + 0x128]
0x2875F: cmp      r8, qword ptr [rdi + 0x10]
0x28763: lea      rcx, [rip + 0x14346]  ; → L"摩o쳌쳌쳌쳌쳌쳌摉o쳌쳌쳌쳌쳌쳌摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌"
0x2876A: cmove    rax, rcx
0x2876E: mov      dword ptr [rsp + 0x50], r13d
0x28773: mov      dword ptr [rsp + 0x48], ebx
0x28777: mov      qword ptr [rsp + 0x40], r14
0x2877C: mov      qword ptr [rsp + 0x38], r8
0x28781: mov      qword ptr [rsp + 0x30], rax
0x28786: mov      qword ptr [rsp + 0x28], rdi
0x2878B: mov      rax, qword ptr [rsp + 0xb8]
0x28793: mov      qword ptr [rsp + 0x20], rax
0x28798: lea      r9, [rsp + 0x2f0]
0x287A0: lea      r8, [rip + 0x15c09]  ; → L"ⴥ㈲㈮猲†景⁯瀥†景⁸瀥†猥┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠ੵ찀쳌쳌慊⁮㐱㈠㈰‶瑡〠㨸㘱㐺‸圠䭄㘠〰⸱㠱〰0쳌쳌쳌쳌剉彐䩍䍟乏剔䱏†┠㌰⁘†漠潦┠⁰漠硦┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠㐭⁵ⴠ┠㠰╘ੳ찀䥓䑖楲敶⁲䜠慵摲䄠敲⁡潃牲灵楴湯†瑓牡⁴〥㘱㙉場†楌業⁴〥㘱㙉場"
0x287A7: mov      edx, 2
0x287AC: lea      ecx, [rdx + 0x4b]
0x287AF: call     qword ptr [rip - 0x135d5]  ; → DbgPrintEx
0x287B5: mov      r8, qword ptr [rsp + 0xa8]
0x287BD: mov      r13d, dword ptr [rsp + 0x94]
0x287C5: jmp      0x287cf
0x287C7: mov      r8, qword ptr [rsp + 0x128]
0x287CF: lea      rax, [r15 + 0x30]
0x287D3: mov      qword ptr [rsp + 0x48], rax
0x287D8: lea      rax, [rsp + 0xf8]
0x287E0: mov      qword ptr [rsp + 0x40], rax
0x287E5: mov      dword ptr [rsp + 0x38], r13d
0x287EA: mov      qword ptr [rsp + 0x30], r14
0x287EF: mov      dword ptr [rsp + 0x28], ebx
0x287F3: mov      qword ptr [rsp + 0x20], r14
0x287F8: mov      r9d, dword ptr [rsp + 0xb0]
0x28800: mov      rdx, r12
0x28803: lea      rcx, [rsp + 0x2f0]
0x2880B: call     0x3bf18
0x28810: mov      r11d, eax
0x28813: mov      dword ptr [rsp + 0x90], eax
0x2881A: jmp      0x28856
0x2881C: mov      r11d, eax
0x2881F: mov      dword ptr [rsp + 0x29c], eax
0x28826: mov      dword ptr [rsp + 0x90], eax
0x2882D: xor      esi, esi
0x2882F: mov      r12, qword ptr [rsp + 0xe0]
0x28837: mov      rdi, qword ptr [rsp + 0xc0]
0x2883F: mov      ebx, dword ptr [rsp + 0xd8]
0x28846: mov      r14, qword ptr [rsp + 0x150]
0x2884E: mov      r15, qword ptr [rsp + 0xe8]
0x28856: cmp      r11d, 0xc0000022
0x2885D: je       0x2886c
0x2885F: cmp      r11d, 0xc0000002
0x28866: jne      0x28e31
0x2886C: mov      rcx, qword ptr [rsp + 0x108]
0x28874: mov      qword ptr [rsp + 0x128], rcx
0x2887C: mov      qword ptr [rsp + 0xa8], rcx
0x28884: mov      qword ptr [rsp + 0x108], rsi
0x2888C: mov      r13d, dword ptr [rsp + 0x94]
0x28894: jmp      0x286cd
0x28899: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x288A4: jmp      0x28e31
0x288A9: cmp      ebx, 0xc  ← IOCTL 0x0C (WRMSR)
0x288AC: jae      0x288ed
0x288AE: bt       dword ptr [r12], 0x1f
0x288B4: jae      0x288dd
0x288B6: mov      qword ptr [rsp + 0x30], 0xc
0x288BF: mov      dword ptr [rsp + 0x28], ebx
0x288C3: mov      qword ptr [rsp + 0x20], r10
0x288C8: lea      r8, [rip + 0x14c21]  ; → L"呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔찀쳌쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†摡⁯瀥†畂⁳祔数┠⁵┨⥵"
0x288CF: mov      edx, 2
0x288D4: mov      ecx, r11d
0x288D7: call     qword ptr [rip - 0x136fd]  ; → DbgPrintEx
0x288DD: mov      dword ptr [rsp + 0x90], 0xc0000023
0x288E8: jmp      0x28e31
0x288ED: cmp      r13d, 8  ← IOCTL 0x08 (RDMSR)
0x288F1: jae      0x28933
0x288F3: bt       dword ptr [r12], 0x1f
0x288F9: jae      0x28923
0x288FB: mov      qword ptr [rsp + 0x30], 8
0x28904: mov      dword ptr [rsp + 0x28], r13d
0x28909: mov      qword ptr [rsp + 0x20], r10
0x2890E: lea      r8, [rip + 0x14c2b]  ; → L"呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔찀쳌쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†摡⁯瀥†畂⁳祔数┠⁵┨⥵
쳌쳌쳌쳌쳌쳌쳌䕇彔义啑剉彙䅄䅔찀쳌쳌쳌쳌쳌쳌쳌䍓䥓䝟呅䥟兎䥕奒䑟呁⁁†景⁯瀥†"
0x28915: mov      edx, 2
0x2891A: mov      ecx, r11d
0x2891D: call     qword ptr [rip - 0x13743]  ; → DbgPrintEx
0x28923: mov      dword ptr [rsp + 0x90], 0xc0000023
0x2892E: jmp      0x28e31
0x28933: cmp      r10, rsi
0x28936: je       0x28e31
0x2893C: mov      r8, qword ptr [r10 + 0x18]
0x28940: mov      qword ptr [rsp + 0xa8], r8
0x28948: cmp      r8, rsi
0x2894B: je       0x28e31
0x28951: lea      rax, [r15 + 0x30]
0x28955: mov      qword ptr [rsp + 0x48], rax
0x2895A: lea      rax, [rsp + 0xf8]
0x28962: mov      qword ptr [rsp + 0x40], rax
0x28967: mov      dword ptr [rsp + 0x38], r13d
0x2896C: mov      qword ptr [rsp + 0x30], r14
0x28971: mov      dword ptr [rsp + 0x28], ebx
0x28975: mov      qword ptr [rsp + 0x20], r14
0x2897A: mov      r9d, 0x2d1400
0x28980: mov      rdx, r12
0x28983: lea      rcx, [rip + 0x14c06]  ; → L"呓剏䝁彅啑剅彙剐偏剅奔찀쳌쳌쳌쳌呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†摡⁯瀥†畂⁳祔数┠⁵┨⥵
쳌쳌쳌쳌쳌쳌쳌䕇彔义啑剉彙䅄䅔찀쳌쳌쳌쳌쳌쳌쳌䍓䥓䝟呅䥟兎䥕奒䑟呁⁁†景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䍓䥓偟十当䡔佒䝕⁈†††景⁯瀥†景⁸瀥†湩異⁴畢"
0x2898A: call     0x3bf18
0x2898F: mov      dword ptr [rsp + 0x90], eax
0x28996: cmp      eax, esi
0x28998: jl       0x28e31
0x2899E: bt       dword ptr [r12], 0xc
0x289A4: jae      0x28e31
0x289AA: mov      rax, qword ptr [r15 + 0x38]
0x289AE: mov      qword ptr [rsp + 0x38], rax
0x289B3: mov      eax, dword ptr [r14 + 0x1c]
0x289B7: mov      dword ptr [rsp + 0x30], eax
0x289BB: mov      rax, qword ptr [rsp + 0xa8]
0x289C3: mov      qword ptr [rsp + 0x28], rax
0x289C8: mov      rdi, qword ptr [rsp + 0xc0]
0x289D0: mov      qword ptr [rsp + 0x20], rdi
0x289D5: mov      r9, qword ptr [rsp + 0xb8]
0x289DD: lea      r8, [rip + 0x14bcc]  ; → L"呓剏䝁彅啑剅彙剐偏剅奔†景⁯瀥†景⁸瀥†摡⁯瀥†畂⁳祔数┠⁵┨⥵
쳌쳌쳌쳌쳌쳌쳌䕇彔义啑剉彙䅄䅔찀쳌쳌쳌쳌쳌쳌쳌䍓䥓䝟呅䥟兎䥕奒䑟呁⁁†景⁯瀥†景⁸瀥†摡⁯瀥†┨⥵
쳌쳌쳌쳌쳌䍓䥓偟十当䡔佒䝕⁈†††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌"
0x289E4: mov      edx, 2
0x289E9: lea      ecx, [rdx + 0x4b]
0x289EC: call     qword ptr [rip - 0x13812]  ; → DbgPrintEx
0x289F2: jmp      0x28e31
0x289F7: cmp      r13d, 0xc  ← IOCTL 0x0C (WRMSR)
0x289FB: jb       0x28e31
0x28A01: cmp      r10, rsi
0x28A04: je       0x28a83
0x28A06: mov      r8, qword ptr [r10 + 0x10]
0x28A0A: mov      qword ptr [rsp + 0xa8], r8
0x28A12: cmp      r8, rsi
0x28A15: je       0x28a83
0x28A17: lea      rax, [r15 + 0x30]
0x28A1B: mov      qword ptr [rsp + 0x48], rax
0x28A20: lea      rax, [rsp + 0xf8]
0x28A28: mov      qword ptr [rsp + 0x40], rax
0x28A2D: mov      dword ptr [rsp + 0x38], r13d
0x28A32: mov      qword ptr [rsp + 0x30], r14
0x28A37: mov      dword ptr [rsp + 0x28], ebx
0x28A3B: mov      qword ptr [rsp + 0x20], r14
0x28A40: mov      r9d, 0x294180
0x28A46: mov      rdx, r12
0x28A49: lea      rcx, [rip + 0x158a0]  ; → L"䕇彔剐䍏卅体归䉏彊义但찀쳌쳌쳌쳌䍁䥐䕟啎彍䡃䱉剄久┠㈰⁘┠⁵┠╣╣╣⁣漠潦┠⁰漠硦┠⁰┠⁳瀥†灩┠⁰ⴥ甲†灯┠⁰甥
쳌쳌쳌쳌쳌쳌䍁䥐䕟啎彍䡃䱉剄久찀쳌쳌쳌쳌쳌쳌䍁䥐䕟䅖彌䕍䡔䑏†㤸㄰찀쳌쳌쳌쳌ⴥ㈲㈮猲†景⁯瀥†景⁸瀥†猥┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠ੵ찀쳌쳌"
0x28A50: call     0x3bf18
0x28A55: mov      dword ptr [rsp + 0x90], eax
0x28A5C: jmp      0x28a7e
0x28A5E: mov      dword ptr [rsp + 0x298], eax
0x28A65: mov      dword ptr [rsp + 0x90], eax
0x28A6C: xor      esi, esi
0x28A6E: mov      r12, qword ptr [rsp + 0xe0]
0x28A76: mov      r15, qword ptr [rsp + 0xe8]
0x28A7E: jmp      0x28e31
0x28A83: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x28A8E: jmp      0x28e31
0x28A93: mov      qword ptr [rsp + 0xf8], 0xffffffffffb3b4c0
0x28A9F: cmp      r10, rsi
0x28AA2: je       0x28aef
0x28AA4: mov      r8, qword ptr [r10 + 0x18]
0x28AA8: mov      qword ptr [rsp + 0xa8], r8
0x28AB0: cmp      r8, rsi
0x28AB3: je       0x28aef
0x28AB5: lea      rax, [r15 + 0x30]
0x28AB9: mov      qword ptr [rsp + 0x38], rax
0x28ABE: lea      rax, [rsp + 0xf8]
0x28AC6: mov      qword ptr [rsp + 0x30], rax
0x28ACB: mov      dword ptr [rsp + 0x28], r13d
0x28AD0: mov      qword ptr [rsp + 0x20], r14
0x28AD5: mov      r9, r15
0x28AD8: mov      rdx, r10
0x28ADB: mov      rcx, r12
0x28ADE: call     0x2ea60
0x28AE3: mov      dword ptr [rsp + 0x90], eax
0x28AEA: jmp      0x28e31
0x28AEF: mov      dword ptr [rsp + 0x90], 0xc00000c0
0x28AFA: jmp      0x28e31
0x28AFF: cmp      ebx, 0x20
0x28B02: jae      0x28b43
0x28B04: bt       dword ptr [r12], 0x1f
0x28B0A: jae      0x28b33
0x28B0C: mov      qword ptr [rsp + 0x30], 0x20
0x28B15: mov      dword ptr [rsp + 0x28], ebx
0x28B19: mov      qword ptr [rsp + 0x20], r10
0x28B1E: lea      r8, [rip + 0x14f9b]  ; → L"䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌䥍䥎佐呒䥟䕄呎䙉Y쳌쳌쳌쳌쳌쳌쳌䥍䥎佐呒剟䅅彄䵓剁彔呁剔䉉S쳌쳌佉呃彌䍓䥓䵟义偉剏彔䕒䑁卟䅍呒呟"
0x28B25: mov      edx, 2
0x28B2A: mov      ecx, r11d
0x28B2D: call     qword ptr [rip - 0x13953]  ; → DbgPrintEx
0x28B33: mov      dword ptr [rsp + 0x90], 0xc0000023
0x28B3E: jmp      0x28e31
0x28B43: mov      eax, 0x210
0x28B48: cmp      r13d, eax
0x28B4B: jae      0x28b89
0x28B4D: bt       dword ptr [r12], 0x1f
0x28B53: jae      0x28b79
0x28B55: mov      qword ptr [rsp + 0x30], rax
0x28B5A: mov      dword ptr [rsp + 0x28], r13d
0x28B5F: mov      qword ptr [rsp + 0x20], r10
0x28B64: lea      r8, [rip + 0x14fa5]  ; → L"䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌䥍䥎佐呒䥟䕄呎䙉Y쳌쳌쳌쳌쳌쳌쳌䥍䥎佐呒剟䅅彄䵓剁彔呁剔䉉S쳌쳌佉呃彌䍓䥓䵟义偉剏彔䕒䑁卟䅍呒呟剈卅佈䑌S쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†摡⁯瀥†浣⁤〥堲†瑦⁲〥"
0x28B6B: mov      edx, 2
0x28B70: mov      ecx, r11d
0x28B73: call     qword ptr [rip - 0x13999]  ; → DbgPrintEx
0x28B79: mov      dword ptr [rsp + 0x90], 0xc0000023
0x28B84: jmp      0x28e31
0x28B89: cmp      r10, rsi
0x28B8C: je       0x28e31
0x28B92: mov      rcx, qword ptr [r10 + 8]
0x28B96: mov      qword ptr [rsp + 0x108], rcx
0x28B9E: cmp      rcx, rsi
0x28BA1: je       0x28e31
0x28BA7: mov      r8, qword ptr [r10 + 0x18]
0x28BAB: mov      qword ptr [rsp + 0xa8], r8
0x28BB3: cmp      r8, rsi
0x28BB6: je       0x28e31
0x28BBC: test     byte ptr [r12 + 8], 1
0x28BC2: je       0x28da2
0x28BC8: cmp      byte ptr [r10 + 0x2e], 0xff
0x28BCD: je       0x28da2
0x28BD3: mov      rdx, qword ptr [r15 + 0x18]
0x28BD7: mov      al, byte ptr [rdx + 0xa]
0x28BDA: cmp      al, 0xec
0x28BDC: jne      0x28c4f
0x28BDE: lea      rax, [r15 + 0x30]
0x28BE2: mov      rcx, qword ptr [rcx + 8]
0x28BE6: add      rcx, 0x38
0x28BEA: mov      qword ptr [rsp + 0x50], rax
0x28BEF: mov      dword ptr [rsp + 0x48], r13d
0x28BF4: mov      dword ptr [rsp + 0x40], ebx
0x28BF8: mov      qword ptr [rsp + 0x38], rdx
0x28BFD: mov      qword ptr [rsp + 0x30], rcx
0x28C02: mov      qword ptr [rsp + 0x28], r8
0x28C07: lea      rax, [rip + 0x14d22]  ; → L"䍓䥓䥄䭓찀쳌쳌쳌䥍䥎佐呒卟䅍呒噟剅䥓乏찀쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉N쳌쳌쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†摡⁯瀥†敖獲潩⁮甥
쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†"
0x28C0E: mov      qword ptr [rsp + 0x20], rax
0x28C13: mov      r9d, 0x1b0501
0x28C19: mov      r8, r10
0x28C1C: mov      rdx, r12
0x28C1F: lea      rcx, [rip + 0x14f3a]  ; → L"䥍䥎佐呒䥟䕄呎䙉Y쳌쳌쳌쳌쳌쳌쳌䥍䥎佐呒剟䅅彄䵓剁彔呁剔䉉S쳌쳌佉呃彌䍓䥓䵟义偉剏彔䕒䑁卟䅍呒呟剈卅佈䑌S쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†摡⁯瀥†浣⁤〥堲†瑦⁲〥堲†剉彐䩍卟千⁉‭〥堸猥
쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔찀쳌쳌쳌쳌쳌䵓剁彔䍒彖剄噉彅"
0x28C26: call     0x3c114
0x28C2B: mov      dword ptr [rsp + 0x90], eax
0x28C32: cmp      eax, esi
0x28C34: jge      0x28e31
0x28C3A: mov      r8, qword ptr [rsp + 0xa8]
0x28C42: mov      r13d, dword ptr [rsp + 0x94]
0x28C4A: jmp      0x28da2
0x28C4F: cmp      al, 0xb0
0x28C51: jne      0x28da2
0x28C57: mov      dil, byte ptr [rdx + 4]
0x28C5B: cmp      dil, 0xd0
0x28C5F: jne      0x28cd2
0x28C61: lea      rax, [r15 + 0x30]
0x28C65: mov      rcx, qword ptr [rcx + 8]
0x28C69: add      rcx, 0x38
0x28C6D: mov      qword ptr [rsp + 0x50], rax
0x28C72: mov      dword ptr [rsp + 0x48], r13d
0x28C77: mov      dword ptr [rsp + 0x40], ebx
0x28C7B: mov      qword ptr [rsp + 0x38], rdx
0x28C80: mov      qword ptr [rsp + 0x30], rcx
0x28C85: mov      qword ptr [rsp + 0x28], r8
0x28C8A: lea      rax, [rip + 0x14c9f]  ; → L"䍓䥓䥄䭓찀쳌쳌쳌䥍䥎佐呒卟䅍呒噟剅䥓乏찀쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉N쳌쳌쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†摡⁯瀥†敖獲潩⁮甥
쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†"
0x28C91: mov      qword ptr [rsp + 0x20], rax
0x28C96: mov      r9d, 0x1b0502
0x28C9C: mov      r8, r10
0x28C9F: mov      rdx, r12
0x28CA2: lea      rcx, [rip + 0x14ed7]  ; → L"䥍䥎佐呒剟䅅彄䵓剁彔呁剔䉉S쳌쳌佉呃彌䍓䥓䵟义偉剏彔䕒䑁卟䅍呒呟剈卅佈䑌S쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†摡⁯瀥†浣⁤〥堲†瑦⁲〥堲†剉彐䩍卟千⁉‭〥堸猥
쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔찀쳌쳌쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†摡⁯瀥†"
0x28CA9: call     0x3c114
0x28CAE: mov      dword ptr [rsp + 0x90], eax
0x28CB5: cmp      eax, esi
0x28CB7: jge      0x28e31
0x28CBD: mov      r8, qword ptr [rsp + 0xa8]
0x28CC5: mov      r13d, dword ptr [rsp + 0x94]
0x28CCD: jmp      0x28da2
0x28CD2: cmp      dil, 0xd1
0x28CD6: jne      0x28d46
0x28CD8: lea      rax, [r15 + 0x30]
0x28CDC: mov      rcx, qword ptr [rcx + 8]
0x28CE0: add      rcx, 0x38
0x28CE4: mov      qword ptr [rsp + 0x50], rax
0x28CE9: mov      dword ptr [rsp + 0x48], r13d
0x28CEE: mov      dword ptr [rsp + 0x40], ebx
0x28CF2: mov      qword ptr [rsp + 0x38], rdx
0x28CF7: mov      qword ptr [rsp + 0x30], rcx
0x28CFC: mov      qword ptr [rsp + 0x28], r8
0x28D01: lea      rax, [rip + 0x14c28]  ; → L"䍓䥓䥄䭓찀쳌쳌쳌䥍䥎佐呒卟䅍呒噟剅䥓乏찀쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉N쳌쳌쳌쳌쳌쳌쳌䵓剁彔䕇彔䕖卒佉⁎†††景⁯瀥†景⁸瀥†摡⁯瀥†敖獲潩⁮甥
쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌䵓剁彔䕓䑎䑟䥒䕖䍟䑍††景⁯瀥†"
0x28D08: mov      qword ptr [rsp + 0x20], rax
0x28D0D: mov      r9d, 0x1b0503
0x28D13: mov      r8, r10
0x28D16: mov      rdx, r12
0x28D19: lea      rcx, [rip + 0x14e80]  ; → L"佉呃彌䍓䥓䵟义偉剏彔䕒䑁卟䅍呒呟剈卅佈䑌S쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†摡⁯瀥†浣⁤〥堲†瑦⁲〥堲†剉彐䩍卟千⁉‭〥堸猥
쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔찀쳌쳌쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†摡⁯瀥†畂晦牥匠穩⁥甥
佉呃彌䥓彖䥄䭓䍟"
0x28D20: call     0x3c114
0x28D25: mov      dword ptr [rsp + 0x90], eax
0x28D2C: cmp      eax, esi
0x28D2E: jge      0x28e31
0x28D34: mov      r8, qword ptr [rsp + 0xa8]
0x28D3C: mov      r13d, dword ptr [rsp + 0x94]
0x28D44: jmp      0x28da2
0x28D46: bt       dword ptr [r12], 0x1d
0x28D4C: jae      0x28da2
0x28D4E: mov      edx, 0xc0000004
0x28D53: mov      ecx, edx
0x28D55: call     0x12acc
0x28D5A: movzx    ecx, dil
0x28D5E: mov      qword ptr [rsp + 0x48], rax
0x28D63: mov      dword ptr [rsp + 0x40], edx
0x28D67: mov      dword ptr [rsp + 0x38], ecx
0x28D6B: mov      dword ptr [rsp + 0x30], 0xb0
0x28D73: mov      qword ptr [rsp + 0x28], r8
0x28D78: mov      qword ptr [rsp + 0x20], r10
0x28D7D: lea      r8, [rip + 0x14e4c]  ; → L"䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†摡⁯瀥†浣⁤〥堲†瑦⁲〥堲†剉彐䩍卟千⁉‭〥堸猥
쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔찀쳌쳌쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†摡⁯瀥†畂晦牥匠穩⁥甥
佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠"
0x28D84: mov      edx, 2
0x28D89: mov      ecx, r11d
0x28D8C: call     qword ptr [rip - 0x13bb2]  ; → DbgPrintEx
0x28D92: mov      r8, qword ptr [rsp + 0xa8]
0x28D9A: mov      r13d, dword ptr [rsp + 0x94]
0x28DA2: lea      rax, [r15 + 0x30]
0x28DA6: mov      qword ptr [rsp + 0x48], rax
0x28DAB: lea      rax, [rsp + 0xf8]
0x28DB3: mov      qword ptr [rsp + 0x40], rax
0x28DB8: mov      dword ptr [rsp + 0x38], r13d
0x28DBD: mov      qword ptr [rsp + 0x30], r14
0x28DC2: mov      dword ptr [rsp + 0x28], ebx
0x28DC6: mov      qword ptr [rsp + 0x20], r14
0x28DCB: mov      r9d, 0x7c088
0x28DD1: mov      rdx, r12
0x28DD4: lea      rcx, [rip + 0x14e55]  ; → L"䵓剁彔䍒彖剄噉彅䅄䅔찀쳌쳌쳌쳌쳌䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†摡⁯瀥†畂晦牥匠穩⁥甥
佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌"
0x28DDB: call     0x3bf18
0x28DE0: mov      dword ptr [rsp + 0x90], eax
0x28DE7: cmp      eax, esi
0x28DE9: jl       0x28e31
0x28DEB: bt       dword ptr [r12], 0xc
0x28DF1: jae      0x28e31
0x28DF3: mov      eax, dword ptr [r14]
0x28DF6: mov      dword ptr [rsp + 0x30], eax
0x28DFA: mov      rax, qword ptr [rsp + 0xa8]
0x28E02: mov      qword ptr [rsp + 0x28], rax
0x28E07: mov      rdi, qword ptr [rsp + 0xc0]
0x28E0F: mov      qword ptr [rsp + 0x20], rdi
0x28E14: mov      r9, qword ptr [rsp + 0xb8]
0x28E1C: lea      r8, [rip + 0x14e2d]  ; → L"䵓剁彔䍒彖剄噉彅䅄䅔††景⁯瀥†景⁸瀥†摡⁯瀥†畂晦牥匠穩⁥甥
佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†湩異⁴畢晦牥琠潯猠慭汬┠⁵‼甥
쳌쳌쳌쳌佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†景⁸瀥†畯灴瑵戠晵敦⁲潴⁯浳污⁬甥㰠┠ੵ찀쳌쳌쳌佉呃彌䥓彖䥄䭓䍟䵓⁉††景⁯瀥†"
0x28E23: mov      edx, 2
0x28E28: lea      ecx, [rdx + 0x4b]
0x28E2B: call     qword ptr [rip - 0x13c51]  ; → DbgPrintEx
0x28E31: mov      rax, qword ptr [rsp + 0xc0]
0x28E39: cmp      rax, rsi
0x28E3C: je       0x28e8b
0x28E3E: mov      r9, qword ptr [rax]
0x28E41: mov      rcx, qword ptr [rax + 0x2f0]
0x28E48: cmp      r9, rcx
0x28E4B: je       0x28e8b
0x28E4D: bt       dword ptr [r12], 0x1f
0x28E53: jae      0x28e77
0x28E55: mov      qword ptr [rsp + 0x20], rcx
0x28E5A: lea      r8, [rip + 0x1560f]  ; → L"䥓䑖楲敶⁲䜠慵摲䄠敲⁡潃牲灵楴湯†瑓牡⁴〥㘱㙉場†楌業⁴〥㘱㙉場
쳌쳌쳌쳌쳌쳌쳌楳彫敧彴慴杲瑥⤨††††摡⁯瀥†摰⁸瀥†潉畂汩卤湹档潲潮獵獆剤煥敵瑳  慦汩摥‬潮瀠潯੬찀쳌쳌쳌楳彫敧彴慴杲瑥⤨††††摡⁯瀥†摰⁸瀥†湐⁐慔杲瑥敄楶散敒慬楴湯映楡敬Ɽ猠獴┠㠰"
0x28E61: mov      edx, 2
0x28E66: lea      ecx, [rdx + 0x4b]
0x28E69: call     qword ptr [rip - 0x13c8f]  ; → DbgPrintEx
0x28E6F: mov      rax, qword ptr [rsp + 0xc0]
0x28E77: movabs   rcx, 0xbadcaffedeadbeef
0x28E81: mov      qword ptr [rax], rcx
0x28E84: mov      qword ptr [rax + 0x2f0], rcx
0x28E8B: lock add dword ptr [r12 + 0x60], 1
0x28E92: mov      ebx, dword ptr [rsp + 0x90]
0x28E99: mov      dword ptr [r15 + 0x30], ebx
0x28E9D: xor      edx, edx
0x28E9F: mov      rcx, r15
0x28EA2: call     qword ptr [rip - 0x13d68]  ; → IofCompleteRequest
0x28EA8: mov      eax, ebx
0x28EAA: mov      rcx, qword ptr [rsp + 0x510]
0x28EB2: xor      rcx, rsp
0x28EB5: call     0x12db0
0x28EBA: lea      r11, [rsp + 0x520]
0x28EC2: mov      rbx, qword ptr [r11 + 0x40]
0x28EC6: mov      rsi, qword ptr [r11 + 0x48]
0x28ECA: mov      rsp, r11
0x28ECD: pop      r15
0x28ECF: pop      r14
0x28ED1: pop      r13
0x28ED3: pop      r12
0x28ED5: pop      rdi
0x28ED6: ret      
