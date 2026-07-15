; ASTRA64.sys - IRP_MJ_CREATE Handler
; Function VA: 0x12480  (RVA 0x2480)
;
; ACCESS CONTROL: **NONE**
; - No SeSinglePrivilegeCheck
; - No process name check
; - No token validation
; - No event gate
;
; This handler simply:
;   1. Creates named notification events (HW64KbdEvent%d, HW64IrqEvent%d)
;   2. Initializes device extension fields to zero
;   3. Returns STATUS_SUCCESS (0)
;
; Any process with admin rights (to call CreateFileW on symlink) gets full access.
; No additional privilege checking occurs after device open.
;
; DriverEntry sets up identical dispatch for all IRP major functions
; (rep stosq fills MajorFunction[0..26] with same handler),
; then overrides IRP_MJ_DEVICE_CONTROL specifically.
;
; === DriverEntry (0x11850) ===
  0000000000011850  53                        push     rbx
  0000000000011851  56                        push     rsi
  0000000000011852  57                        push     rdi
  0000000000011853  4883ec20                  sub      rsp, 0x20
  0000000000011857  488bf1                    mov      rsi, rcx
  000000000001185A  33db                      xor      ebx, ebx
  000000000001185C  891d1e280000              mov      dword ptr [rip + 0x281e], ebx
  0000000000011862  488d3d97270000            lea      rdi, [rip + 0x2797]
  0000000000011869  4863c3                    movsxd   rax, ebx
  000000000001186C  4c8d04c7                  lea      r8, [rdi + rax*8]
  0000000000011870  8bd3                      mov      edx, ebx
  0000000000011872  488bce                    mov      rcx, rsi
  0000000000011875  e886f7ffff                call     0x11000
  000000000001187A  8b0d00280000              mov      ecx, dword ptr [rip + 0x2800]
  0000000000011880  85c0                      test     eax, eax
  0000000000011882  7c11                      jl       0x11895
  0000000000011884  83c101                    add      ecx, 1
  0000000000011887  890df3270000              mov      dword ptr [rip + 0x27f3], ecx
  000000000001188D  83c301                    add      ebx, 1
  0000000000011890  83fb0f                    cmp      ebx, 0xf
  0000000000011893  7ed4                      jle      0x11869
  0000000000011895  85c9                      test     ecx, ecx
  0000000000011897  742e                      je       0x118c7
  0000000000011899  488d7e70                  lea      rdi, [rsi + 0x70]
  000000000001189D  488d05dcf9ffff            lea      rax, [rip - 0x624]
  00000000000118A4  b91b000000                mov      ecx, 0x1b
  00000000000118A9  f348ab                    rep stosq qword ptr [rdi], rax
  00000000000118AC  488d05dd010000            lea      rax, [rip + 0x1dd]
  00000000000118B3  48898688000000            mov      qword ptr [rsi + 0x88], rax
  00000000000118BA  488d054fffffff            lea      rax, [rip - 0xb1]
  00000000000118C1  48894668                  mov      qword ptr [rsi + 0x68], rax
  00000000000118C5  33c0                      xor      eax, eax
  00000000000118C7  4883c420                  add      rsp, 0x20
  00000000000118CB  5f                        pop      rdi
  00000000000118CC  5e                        pop      rsi
  00000000000118CD  5b                        pop      rbx
  00000000000118CE  c3                        ret      
;
; === IRP_MJ_CREATE handler (0x12480) ===
  0000000000012480  53                        push     rbx
  0000000000012481  56                        push     rsi
  0000000000012482  57                        push     rdi
  0000000000012483  4154                      push     r12
  0000000000012485  4881ecf8000000            sub      rsp, 0xf8
  000000000001248C  498bf8                    mov      rdi, r8
  000000000001248F  488bda                    mov      rbx, rdx
  0000000000012492  4533e4                    xor      r12d, r12d
  0000000000012495  4c89642420                mov      qword ptr [rsp + 0x20], r12
  000000000001249A  4c89642428                mov      qword ptr [rsp + 0x28], r12
  000000000001249F  448b4b0c                  mov      r9d, dword ptr [rbx + 0xc]
  00000000000124A3  4c8d0516010000            lea      r8, [rip + 0x116]
  00000000000124AA  be28000000                mov      esi, 0x28
  00000000000124AF  488bd6                    mov      rdx, rsi
  00000000000124B2  488d4c2450                lea      rcx, [rsp + 0x50]
  00000000000124B7  ff15730b0000              call     qword ptr [rip + 0xb73]  ; _snwprintf
  00000000000124BD  488d542450                lea      rdx, [rsp + 0x50]
  00000000000124C2  488d4c2430                lea      rcx, [rsp + 0x30]
  00000000000124C7  ff155b0b0000              call     qword ptr [rip + 0xb5b]  ; RtlInitUnicodeString
  00000000000124CD  488d542420                lea      rdx, [rsp + 0x20]
  00000000000124D2  488d4c2430                lea      rcx, [rsp + 0x30]
  00000000000124D7  ff15d30b0000              call     qword ptr [rip + 0xbd3]  ; IoCreateNotificationEvent
  00000000000124DD  48894360                  mov      qword ptr [rbx + 0x60], rax
  00000000000124E1  448b4b0c                  mov      r9d, dword ptr [rbx + 0xc]
  00000000000124E5  4c8d0584000000            lea      r8, [rip + 0x84]
  00000000000124EC  488bd6                    mov      rdx, rsi
  00000000000124EF  488d8c24a0000000          lea      rcx, [rsp + 0xa0]
  00000000000124F7  ff15330b0000              call     qword ptr [rip + 0xb33]  ; _snwprintf
  00000000000124FD  488d9424a0000000          lea      rdx, [rsp + 0xa0]
  0000000000012505  488d4c2440                lea      rcx, [rsp + 0x40]
  000000000001250A  ff15180b0000              call     qword ptr [rip + 0xb18]  ; RtlInitUnicodeString
  0000000000012510  488d542428                lea      rdx, [rsp + 0x28]
  0000000000012515  488d4c2440                lea      rcx, [rsp + 0x40]
  000000000001251A  ff15900b0000              call     qword ptr [rip + 0xb90]  ; IoCreateNotificationEvent
  0000000000012520  48898398000000            mov      qword ptr [rbx + 0x98], rax
  0000000000012527  4489a3cc000000            mov      dword ptr [rbx + 0xcc], r12d
  000000000001252E  4489a3a0000000            mov      dword ptr [rbx + 0xa0], r12d
  0000000000012535  4c89a3a8000000            mov      qword ptr [rbx + 0xa8], r12
  000000000001253C  4c89a3b0000000            mov      qword ptr [rbx + 0xb0], r12
  0000000000012543  4c89a3b8000000            mov      qword ptr [rbx + 0xb8], r12
  000000000001254A  4c89a3c0000000            mov      qword ptr [rbx + 0xc0], r12
  0000000000012551  44886358                  mov      byte ptr [rbx + 0x58], r12b
  0000000000012555  4c896738                  mov      qword ptr [rdi + 0x38], r12
  0000000000012559  33c0                      xor      eax, eax
  000000000001255B  4881c4f8000000            add      rsp, 0xf8
  0000000000012562  415c                      pop      r12
  0000000000012564  5f                        pop      rdi
  0000000000012565  5e                        pop      rsi
  0000000000012566  5b                        pop      rbx
  0000000000012567  c3                        ret      
