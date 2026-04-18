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
    mov     eax, 0x2C       ; NtTerminateProcess syscall number (Windows 10/11 x64)
    syscall
    int     3
vision_nt_exit ENDP

END
