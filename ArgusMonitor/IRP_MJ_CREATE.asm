; ArgusMonitor.sys IRP_MJ_CREATE handler disassembly
; Handler RVA: 0x1000
; Access Control: NONE
; Notes: IRP_MJ_CREATE is trivial (returns immediately) - NO access control
;
; Privilege checks found: 0
; Process checks found: 0
;
  0000000140001000  4883ec28                  sub rsp, 0x28
  0000000140001004  488bca                    mov rcx, rdx
  0000000140001007  c7423000000000            mov dword ptr [rdx + 0x30], 0
  000000014000100E  48c7423800000000          mov qword ptr [rdx + 0x38], 0
  0000000140001016  33d2                      xor edx, edx
  0000000140001018  ff151ac00000              call qword ptr [rip + 0xc01a]
  000000014000101E  33c0                      xor eax, eax
  0000000140001020  4883c428                  add rsp, 0x28
  0000000140001024  c3                        ret 
