.CODE

ALIGN 16
vision_nt_syscall PROC
    mov     r10, rcx
    mov     eax, ecx
    syscall
    ret
vision_nt_syscall ENDP

ALIGN 16
vision_nt_exit PROC
    mov     rdx, rcx
    mov     rcx, -1
    ; TODO: patch rax with correct NtTerminateProcess syscall number at runtime
    xor     eax, eax        ; placeholder — will be patched
    syscall
    int     3
vision_nt_exit ENDP

END
