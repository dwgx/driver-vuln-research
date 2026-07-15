; SIVX64.sys IRP_MJ_CREATE handler — access control logic
; Checks SeLoadDriverPrivilege via SeSinglePrivilegeCheck
; Function: RVA 0x111C8 - 0x11888

0x211C8: mov      r11, rsp
0x211CB: mov      qword ptr [r11 + 0x10], rdx
0x211CF: push     rbx
0x211D0: push     rbp
0x211D1: push     rsi
0x211D2: push     rdi
0x211D3: push     r12
0x211D5: push     r13
0x211D7: push     r14
0x211D9: sub      rsp, 0xe0
0x211E0: mov      rax, qword ptr [rdx + 0xb8]
0x211E7: mov      rdi, qword ptr [rcx + 0x40]
0x211EB: mov      r14, qword ptr [rax + 0x30]
0x211EF: and      qword ptr [r11 + 8], 0
0x211F4: test     r14, r14
0x211F7: je       0x21204
0x211F9: lea      r12, [r14 + 0x58]
0x211FD: movzx    ebx, word ptr [r12]
0x21202: jmp      0x21209
0x21204: xor      r12d, r12d
0x21207: xor      ebx, ebx
0x21209: test     ebx, ebx
0x2120B: je       0x21242
0x2120D: bt       dword ptr [rdi + 8], 0x16
0x21212: jae      0x21242
0x21214: mov      rcx, qword ptr [r12 + 8]
0x21219: lea      rdx, [rip + 0x1b700]  ; → L"\GPIO-EXT"
0x21220: call     qword ptr [rip - 0xbff6]  ; → _wcsicmp
0x21226: test     eax, eax
0x21228: je       0x21240
0x2122A: mov      rcx, qword ptr [r12 + 8]
0x2122F: lea      rdx, [rip + 0x1b70a]  ; → L"\GPIO-INT"
0x21236: call     qword ptr [rip - 0xc00c]  ; → _wcsicmp
0x2123C: test     eax, eax
0x2123E: jne      0x21242
0x21240: xor      ebx, ebx
0x21242: test     r14, r14
0x21245: je       0x21265
0x21247: mov      rcx, qword ptr [rip - 0x597e]
0x2124E: mov      dl, 1
0x21250: call     qword ptr [rip - 0xc03e]  ; → SeSinglePrivilegeCheck
0x21256: test     al, al
0x21258: jne      0x21265
0x2125A: mov      r13d, 0xc0000022
0x21260: jmp      0x21857
0x21265: test     ebx, ebx
0x21267: je       0x2182d
0x2126D: lea      r9, [rsp + 0x120]
0x21275: lea      r8, [rsp + 0xb8]
0x2127D: mov      edx, 1
0x21282: mov      rcx, r12
0x21285: call     qword ptr [rip - 0xc173]  ; → IoGetDeviceObjectPointer
0x2128B: mov      ebx, 0x4d
0x21290: test     eax, eax
0x21292: mov      r13d, eax
0x21295: js       0x212c7
0x21297: mov      rcx, qword ptr [rsp + 0x120]
0x2129F: lea      rsi, [rip + 0x1b6da]  ; → L"䑇偏†찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†⸥匪
쳌쳌쳌쳌쳌쳌传䕐⁎찀쳌쳌쳌쳌†䍁䥐찀쳌쳌쳌쳌†䍐敉찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅䘠䥁⁌††景⁯瀥†ⴥ〲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†䙏⁘汁潬慣楴湯䘠楡敬੤찀쳌"
0x212A6: mov      qword ptr [rsp + 0x130], rsi
0x212AE: call     qword ptr [rip - 0xc134]  ; → ObfReferenceObject
0x212B4: mov      rcx, qword ptr [rsp + 0xb8]
0x212BC: call     qword ptr [rip - 0xc132]  ; → ObfDereferenceObject
0x212C2: jmp      0x213a0
0x212C7: lea      rsi, [rip + 0x1b6f2]  ; → L"传䕐⁎찀쳌쳌쳌쳌†䍁䥐찀쳌쳌쳌쳌†䍐敉찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅䘠䥁⁌††景⁯瀥†ⴥ〲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†䙏⁘汁潬慣楴湯䘠楡敬੤찀쳌"
0x212CE: mov      rdx, r12
0x212D1: mov      rcx, rdi
0x212D4: mov      qword ptr [rsp + 0x130], rsi
0x212DC: call     0x2dd44
0x212E1: test     rax, rax
0x212E4: mov      qword ptr [rsp + 0x120], rax
0x212EC: jne      0x2139d
0x212F2: mov      rdx, qword ptr [rdi + 0x10d0]
0x212F9: lea      rsi, [rip + 0x1b6d0]  ; → L"†䍁䥐찀쳌쳌쳌쳌†䍐敉찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅䘠䥁⁌††景⁯瀥†ⴥ〲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†䙏⁘汁潬慣楴湯䘠楡敬੤찀쳌"
0x21300: mov      r8, r12
0x21303: mov      rcx, rdi
0x21306: mov      qword ptr [rsp + 0x130], rsi
0x2130E: call     0x2de30
0x21313: test     rax, rax
0x21316: mov      qword ptr [rsp + 0x120], rax
0x2131E: jne      0x2139d
0x21320: mov      rdx, qword ptr [rdi + 0x10d8]
0x21327: lea      rsi, [rip + 0x1b6b2]  ; → L"†䍐敉찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅䘠䥁⁌††景⁯瀥†ⴥ〲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†䙏⁘汁潬慣楴湯䘠楡敬੤찀쳌"
0x2132E: mov      r8, r12
0x21331: mov      rcx, rdi
0x21334: mov      qword ptr [rsp + 0x130], rsi
0x2133C: call     0x2de30
0x21341: test     rax, rax
0x21344: mov      qword ptr [rsp + 0x120], rax
0x2134C: jne      0x2139d
0x2134E: bt       dword ptr [rdi], 0x1f
0x21352: jae      0x2184d
0x21358: mov      ecx, r13d
0x2135B: call     0x12acc
0x21360: movzx    ecx, word ptr [r12]
0x21365: lea      r8, [rip + 0x1b684]  ; → L"剉彐䩍䍟䕒呁⁅䘠䥁⁌††景⁯瀥†ⴥ〲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†䙏⁘汁潬慣楴湯䘠楡敬੤찀쳌"
0x2136C: mov      qword ptr [rsp + 0x38], rax
0x21371: mov      rax, qword ptr [r12 + 8]
0x21376: shr      rcx, 1
0x21379: mov      dword ptr [rsp + 0x30], r13d
0x2137E: mov      qword ptr [rsp + 0x28], rax
0x21383: mov      qword ptr [rsp + 0x20], rcx
0x21388: mov      ecx, ebx
0x2138A: mov      r9, r14
0x2138D: mov      edx, 2
0x21392: call     qword ptr [rip - 0xc1b8]  ; → DbgPrintEx
0x21398: jmp      0x2184d
0x2139D: xor      r13d, r13d
0x213A0: test     byte ptr [rdi], 1
0x213A3: je       0x213d8
0x213A5: movzx    ecx, word ptr [r12]
0x213AA: mov      rax, qword ptr [r12 + 8]
0x213AF: lea      r8, [rip + 0x1b5da]  ; → L"剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†⸥匪
쳌쳌쳌쳌쳌쳌传䕐⁎찀쳌쳌쳌쳌†䍁䥐찀쳌쳌쳌쳌†䍐敉찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅䘠䥁⁌††景⁯瀥†ⴥ〲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†䙏⁘汁潬慣楴湯䘠楡敬੤찀쳌"
0x213B6: shr      rcx, 1
0x213B9: mov      qword ptr [rsp + 0x30], rax
0x213BE: mov      r9, rsi
0x213C1: mov      qword ptr [rsp + 0x28], rcx
0x213C6: mov      ecx, ebx
0x213C8: mov      edx, 2
0x213CD: mov      qword ptr [rsp + 0x20], r14
0x213D2: call     qword ptr [rip - 0xc1f8]  ; → DbgPrintEx
0x213D8: mov      ecx, dword ptr [rdi + 0x40]
0x213DB: mov      edx, 0x320
0x213E0: call     qword ptr [rip - 0xc2be]  ; → ExAllocatePool
0x213E6: test     rax, rax
0x213E9: mov      rbp, rax
0x213EC: je       0x217ef
0x213F2: lock add dword ptr [rdi + 0x68], 1
0x213F7: xor      edx, edx
0x213F9: mov      r8d, 0x320
0x213FF: mov      rcx, rax
0x21402: call     0x13580
0x21407: movabs   r11, 0xbadcaffedeadbeef
0x21411: mov      qword ptr [rbp], r11
0x21415: mov      qword ptr [rbp + 0x2f0], r11
0x2141C: mov      qword ptr [r14 + 0x18], rbp
0x21420: mov      rcx, qword ptr [rsp + 0x120]
0x21428: call     qword ptr [rdi + 0x160]
0x2142E: test     rax, rax
0x21431: mov      rsi, rax
0x21434: je       0x21474
0x21436: cmp      dword ptr [rsi + 0x48], 0x32
0x2143A: jne      0x21457
0x2143C: mov      rax, qword ptr [rsi + 0x40]
0x21440: test     rax, rax
0x21443: je       0x21457
0x21445: cmp      dword ptr [rax + 8], 0x5f534750
0x2144C: je       0x21474
0x2144E: cmp      dword ptr [rax + 0x10], 0x5f534750
0x21455: je       0x21474
0x21457: mov      rcx, rsi
0x2145A: mov      rbx, rsi
0x2145D: call     qword ptr [rdi + 0x160]
0x21463: mov      rcx, rbx
0x21466: mov      rsi, rax
0x21469: call     qword ptr [rip - 0xc2df]  ; → ObfDereferenceObject
0x2146F: test     rsi, rsi
0x21472: jne      0x21436
0x21474: mov      rcx, qword ptr [rsp + 0x120]
0x2147C: call     qword ptr [rdi + 0x158]
0x21482: test     rax, rax
0x21485: mov      rbx, rax
0x21488: je       0x214a3
0x2148A: test     rsi, rsi
0x2148D: jne      0x214c5
0x2148F: cmp      dword ptr [rax + 0x48], 0x32
0x21493: je       0x2149b
0x21495: cmp      dword ptr [rax + 0x48], 4
0x21499: jne      0x214a8
0x2149B: mov      rsi, rax
0x2149E: mov      rcx, rax
0x214A1: jmp      0x214bf
0x214A3: test     rsi, rsi
0x214A6: jne      0x214c5
0x214A8: mov      rcx, qword ptr [rsp + 0x120]
0x214B0: cmp      dword ptr [rcx + 0x48], 0x32
0x214B4: je       0x214bc
0x214B6: cmp      dword ptr [rcx + 0x48], 0x22
0x214BA: jne      0x214c5
0x214BC: mov      rsi, rcx
0x214BF: call     qword ptr [rip - 0xc345]  ; → ObfReferenceObject
0x214C5: lea      rdx, [rip + 0x1b5a4]
0x214CC: lea      rcx, [rsp + 0xc8]
0x214D4: call     qword ptr [rip - 0xc46a]  ; → RtlInitUnicodeString
0x214DA: test     rbx, rbx
0x214DD: mov      dword ptr [rbp + 0x20], 0xa
0x214E4: mov      qword ptr [rbp + 8], rbx
0x214E8: mov      qword ptr [rbp + 0x10], rsi
0x214EC: mov      rax, qword ptr [rsp + 0x120]
0x214F4: mov      qword ptr [rbp + 0x18], rax
0x214F8: je       0x21504
0x214FA: mov      r10, qword ptr [rbx + 8]
0x214FE: add      r10, 0x38
0x21502: jmp      0x2150c
0x21504: lea      r10, [rsp + 0xc8]
0x2150C: test     rsi, rsi
0x2150F: mov      qword ptr [rsp + 0xa8], r10
0x21517: je       0x21523
0x21519: mov      rdx, qword ptr [rsi + 8]
0x2151D: add      rdx, 0x38
0x21521: jmp      0x2152b
0x21523: lea      rdx, [rsp + 0xc8]
0x2152B: mov      r11, qword ptr [rsp + 0x120]
0x21533: mov      rax, rsi
0x21536: mov      qword ptr [rsp + 0x138], rdx
0x2153E: mov      r9, qword ptr [r11 + 8]
0x21542: add      r9, 0x38
0x21546: neg      rax
0x21549: sbb      ecx, ecx
0x2154B: mov      qword ptr [rsp + 0xc0], r9
0x21553: and      ecx, 2
0x21556: add      ecx, 2
0x21559: test     dword ptr [rdi], ecx
0x2155B: je       0x216ab
0x21561: test     rsi, rsi
0x21564: lea      rax, [rip + 0x1b535]  ; → L"† 쳌쳌쳌쳌쳌쳌摩o쳌쳌쳌쳌쳌쳌摉o쳌쳌쳌쳌쳌쳌摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥"
0x2156B: mov      qword ptr [rsp + 0xb0], rax
0x21573: je       0x2158c
0x21575: bt       dword ptr [rsi + 0x30], 0xc
0x2157A: lea      rcx, [rip + 0x1b52f]  ; → L"摩o쳌쳌쳌쳌쳌쳌摉o쳌쳌쳌쳌쳌쳌摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌"
0x21581: lea      rax, [rip + 0x1b538]  ; → L"摉o쳌쳌쳌쳌쳌쳌摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌剉彐䩍䍟佌䕓††"
0x21588: cmovb    rax, rcx
0x2158C: test     rbx, rbx
0x2158F: mov      qword ptr [rsp + 0xa0], rax
0x21597: je       0x215b8
0x21599: bt       dword ptr [rbx + 0x30], 0xc
0x2159E: lea      rcx, [rip + 0x1b52b]  ; → L"摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌剉彐䩍䍟佌䕓††††††景⁯瀥†"
0x215A5: lea      rax, [rip + 0x1b534]  ; → L"摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌剉彐䩍䍟佌䕓††††††景⁯瀥†景⁸瀥†摢⁯瀥†"
0x215AC: cmovb    rax, rcx
0x215B0: mov      qword ptr [rsp + 0xb0], rax
0x215B8: movzx    r8d, word ptr [r12]
0x215BD: movzx    r9d, word ptr [r9]
0x215C1: movzx    edx, word ptr [rdx]
0x215C4: movzx    r10d, word ptr [r10]
0x215C8: shr      r8, 1
0x215CB: shr      r9, 1
0x215CE: bt       dword ptr [r11 + 0x30], 0xc
0x215D4: lea      rax, [rip + 0x1b4a5]  ; → L"摁o쳌쳌쳌쳌쳌쳌摡o쳌쳌쳌쳌쳌쳌† 쳌쳌쳌쳌쳌쳌摩o쳌쳌쳌쳌쳌쳌摉o쳌쳌쳌쳌쳌쳌摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠"
0x215DB: lea      rcx, [rip + 0x1b4ae]  ; → L"摡o쳌쳌쳌쳌쳌쳌† 쳌쳌쳌쳌쳌쳌摩o쳌쳌쳌쳌쳌쳌摉o쳌쳌쳌쳌쳌쳌摢o쳌쳌쳌쳌쳌쳌摂o쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景"
0x215E2: cmovb    rcx, rax
0x215E6: mov      rax, qword ptr [r12 + 8]
0x215EB: mov      r12, qword ptr [rsp + 0x130]
0x215F3: mov      qword ptr [rsp + 0x98], rax
0x215FB: mov      rax, qword ptr [rsp + 0xc0]
0x21603: mov      qword ptr [rsp + 0x90], r8
0x2160B: mov      rax, qword ptr [rax + 8]
0x2160F: shr      rdx, 1
0x21612: shr      r10, 1
0x21615: mov      qword ptr [rsp + 0x88], rax
0x2161D: mov      rax, qword ptr [rsp + 0x138]
0x21625: mov      qword ptr [rsp + 0x80], r9
0x2162D: mov      rax, qword ptr [rax + 8]
0x21631: mov      qword ptr [rsp + 0x78], r11
0x21636: mov      qword ptr [rsp + 0x70], rcx
0x2163B: mov      qword ptr [rsp + 0x68], rax
0x21640: mov      rax, qword ptr [rsp + 0xa0]
0x21648: mov      qword ptr [rsp + 0x60], rdx
0x2164D: mov      qword ptr [rsp + 0x58], rsi
0x21652: mov      qword ptr [rsp + 0x50], rax
0x21657: mov      rax, qword ptr [rsp + 0xa8]
0x2165F: mov      rax, qword ptr [rax + 8]
0x21663: mov      edx, 2
0x21668: lea      r8, [rip + 0x1b481]  ; → L"剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†猥┠⁰┠㈭⸰匪†⸥匪
쳌쳌佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌剉彐䩍䍟佌䕓††††††景⁯瀥†景⁸瀥†摢⁯瀥†摩⁯瀥†摡⁯瀥
"
0x2166F: mov      qword ptr [rsp + 0x48], rax
0x21674: mov      rax, qword ptr [rsp + 0xb0]
0x2167C: mov      qword ptr [rsp + 0x40], r10
0x21681: mov      qword ptr [rsp + 0x38], rbx
0x21686: mov      qword ptr [rsp + 0x30], rax
0x2168B: lea      ecx, [rdx + 0x4b]
0x2168E: mov      r9, r12
0x21691: mov      qword ptr [rsp + 0x28], rbp
0x21696: mov      qword ptr [rsp + 0x20], r14
0x2169B: call     qword ptr [rip - 0xc4c1]  ; → DbgPrintEx
0x216A1: mov      r11, qword ptr [rsp + 0x120]
0x216A9: jmp      0x216b3
0x216AB: mov      r12, qword ptr [rsp + 0x130]
0x216B3: test     rbx, rbx
0x216B6: je       0x21780
0x216BC: cmp      dword ptr [rbx + 0x48], 7
0x216C0: je       0x216ce
0x216C2: mov      dword ptr [rbp + 0x24], 0xc0000010
0x216C9: jmp      0x2184d
0x216CE: bt       dword ptr [rbx + 0x30], 0xc
0x216D3: jae      0x217a8
0x216D9: mov      rax, qword ptr [rsp + 0x128]
0x216E1: lea      rcx, [rbp + 0x28]
0x216E5: mov      r9d, 0x41018
0x216EB: add      rax, 0x30
0x216EF: mov      r8, r11
0x216F2: mov      rdx, rdi
0x216F5: mov      qword ptr [rsp + 0x48], rax
0x216FA: xor      eax, eax
0x216FC: mov      qword ptr [rsp + 0x40], rax
0x21701: mov      dword ptr [rsp + 0x38], 8
0x21709: mov      qword ptr [rsp + 0x30], rcx
0x2170E: mov      dword ptr [rsp + 0x28], eax
0x21712: lea      rcx, [rip + 0x1b437]  ; → L"佉呃彌䍓䥓䝟呅䅟䑄䕒卓찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌剉彐䩍䍟佌䕓††††††景⁯瀥†景⁸瀥†摢⁯瀥†摩⁯瀥†摡⁯瀥
剉彐䩍䍟佌䕓††††††景⁯瀥
剉彐䩍䍟乏剔䱏†┠㌰⁘†漠潦┠⁰漠硦┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠"
0x21719: mov      qword ptr [rsp + 0x20], rax
0x2171E: call     0x3bf18
0x21723: test     eax, eax
0x21725: mov      dword ptr [rbp + 0x24], eax
0x21728: js       0x2184d
0x2172E: test     byte ptr [rdi], 1
0x21731: je       0x2184d
0x21737: movzx    edx, byte ptr [rbp + 0x2d]
0x2173B: movzx    ecx, byte ptr [rbp + 0x2e]
0x2173F: movzx    r8d, byte ptr [rbp + 0x2c]
0x21744: movzx    eax, byte ptr [rbp + 0x2f]
0x21748: mov      r9, r12
0x2174B: mov      dword ptr [rsp + 0x48], eax
0x2174F: mov      dword ptr [rsp + 0x40], ecx
0x21753: mov      dword ptr [rsp + 0x38], edx
0x21757: mov      dword ptr [rsp + 0x30], r8d
0x2175C: mov      edx, 2
0x21761: lea      r8, [rip + 0x1b408]  ; → L"剉彐䩍䍟䕒呁⁅┠㘭⁳†摯⁯瀥†景⁸瀥†摡⁤㈥⹵甥┮⹵甥
쳌쳌쳌쳌剉彐䩍䍟佌䕓††††††景⁯瀥†景⁸瀥†摢⁯瀥†摩⁯瀥†摡⁯瀥
剉彐䩍䍟佌䕓††††††景⁯瀥
剉彐䩍䍟乏剔䱏†┠㌰⁘†漠潦┠⁰漠硦┠⁰戠晵┠⁰椠汰┠㐭⁵漠汰┠ੵ찀쳌쳌쳌쳌쳌쳌㕖㠮‵䈠極瑬䨠湡"
0x21768: lea      ecx, [rdx + 0x4b]
0x2176B: mov      qword ptr [rsp + 0x28], rbp
0x21770: mov      qword ptr [rsp + 0x20], r14
0x21775: call     qword ptr [rip - 0xc59b]  ; → DbgPrintEx
0x2177B: jmp      0x2184d
0x21780: cmp      dword ptr [rdi + 0x78], 0x818
0x21787: jb       0x217a8
0x21789: cmp      dword ptr [rdi + 0x78], 0x893
0x21790: ja       0x217a8
0x21792: cmp      dword ptr [r11 + 0x48], 0x32
0x21797: je       0x2184d
0x2179D: cmp      dword ptr [r11 + 0x48], 0x22
0x217A2: je       0x2184d
0x217A8: test     r11, r11
0x217AB: je       0x217b6
0x217AD: mov      rcx, r11
0x217B0: call     qword ptr [rip - 0xc626]  ; → ObfDereferenceObject
0x217B6: test     rsi, rsi
0x217B9: je       0x217c4
0x217BB: mov      rcx, rsi
0x217BE: call     qword ptr [rip - 0xc634]  ; → ObfDereferenceObject
0x217C4: test     rbx, rbx
0x217C7: je       0x217d2
0x217C9: mov      rcx, rbx
0x217CC: call     qword ptr [rip - 0xc642]  ; → ObfDereferenceObject
0x217D2: and      qword ptr [r14 + 0x18], 0
0x217D7: xor      edx, edx
0x217D9: mov      rcx, rbp
0x217DC: call     qword ptr [rip - 0xc7b2]  ; → ExFreePoolWithTag
0x217E2: lock add dword ptr [rdi + 0x6c], 1
0x217E7: mov      r13d, 0xc0000034
0x217ED: jmp      0x21857
0x217EF: mov      rcx, qword ptr [rsp + 0x120]
0x217F7: call     qword ptr [rip - 0xc66d]  ; → ObfDereferenceObject
0x217FD: bt       dword ptr [rdi], 0x1f
0x21801: jae      0x21825
0x21803: and      qword ptr [rsp + 0x28], 0
0x21809: lea      r8, [rip + 0x1b220]  ; → L"剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†䙏⁘汁潬慣楴湯䘠楡敬੤찀쳌"
0x21810: mov      r9, rsi
0x21813: mov      edx, 2
0x21818: mov      ecx, ebx
0x2181A: mov      qword ptr [rsp + 0x20], r14
0x2181F: call     qword ptr [rip - 0xc645]  ; → DbgPrintEx
0x21825: mov      r13d, 0xc000009a
0x2182B: jmp      0x21857
0x2182D: test     byte ptr [rdi], 1
0x21830: je       0x2184a
0x21832: mov      edx, 2
0x21837: lea      r8, [rip + 0x1b122]  ; → L"剉彐䩍䍟䕒呁⁅†††††景⁯瀥
䑇偏†찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†⸥匪
쳌쳌쳌쳌쳌쳌传䕐⁎찀쳌쳌쳌쳌†䍁䥐찀쳌쳌쳌쳌†䍐敉찀쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅䘠䥁⁌††景⁯瀥†ⴥ〲⨮⁓‭〥堸猥
쳌쳌쳌쳌쳌쳌쳌剉彐䩍䍟䕒呁⁅┠㘭⁳†景⁯瀥†景⁸瀥†䙏⁘汁潬慣"
0x2183E: mov      r9, r14
0x21841: lea      ecx, [rdx + 0x4b]
0x21844: call     qword ptr [rip - 0xc66a]  ; → DbgPrintEx
0x2184A: xor      r13d, r13d
0x2184D: test     r13d, r13d
0x21850: js       0x21857
0x21852: lock add dword ptr [rdi + 0x5c], 1
0x21857: mov      rax, qword ptr [rsp + 0x128]
0x2185F: xor      edx, edx
0x21861: and      qword ptr [rax + 0x38], 0
0x21866: mov      rcx, rax
0x21869: mov      dword ptr [rax + 0x30], r13d
0x2186D: call     qword ptr [rip - 0xc733]  ; → IofCompleteRequest
0x21873: mov      eax, r13d
0x21876: add      rsp, 0xe0
0x2187D: pop      r14
0x2187F: pop      r13
0x21881: pop      r12
0x21883: pop      rdi
0x21884: pop      rsi
0x21885: pop      rbp
0x21886: pop      rbx
0x21887: ret      
