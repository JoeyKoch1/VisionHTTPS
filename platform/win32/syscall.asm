; platform/win32/syscall.asm  (MASM x64)
; ─────────────────────────────────────────────────────────────────────────────
; Windows NT syscall ABI (x64):
;   syscall number  → rax
;   args            → rcx, rdx, r8, r9, then stack (shadow space required)
;   return value    → rax (NTSTATUS)
;
; NOTE: NT syscall numbers CHANGE between Windows versions.
;       Phase 2 will resolve them at runtime by parsing ntdll.dll's EAT.
;       These stubs are the call-site plumbing — number injection happens
;       from C via a runtime-patched table.
; ─────────────────────────────────────────────────────────────────────────────

.CODE

; vision_nt_syscall(nr, a1, a2, a3, a4)
; Maps to:  rax=nr, rcx=a1, rdx=a2, r8=a3, r9=a4
ALIGN 16
vision_nt_syscall PROC
    mov     r10, rcx        ; Windows kernel expects orig rcx in r10
    mov     eax, ecx        ; nr (first arg on Win64 = rcx)
    syscall
    ret
vision_nt_syscall ENDP

; vision_nt_exit(code)
; NtTerminateProcess(NtCurrentProcess(), code)
; We pass -1 as handle (NtCurrentProcess pseudo-handle)
ALIGN 16
vision_nt_exit PROC
    ; rcx = exit_code (first arg from C)
    mov     rdx, rcx        ; ExitStatus = code
    mov     rcx, -1         ; ProcessHandle = NtCurrentProcess()
    ; TODO: patch rax with correct NtTerminateProcess syscall number at runtime
    xor     eax, eax        ; placeholder — will be patched
    syscall
    int     3               ; unreachable, but stops speculative execution
vision_nt_exit ENDP

END
