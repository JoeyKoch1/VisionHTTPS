; platform/linux/syscall.asm
; ─────────────────────────────────────────────────────────────────────────────
; Raw Linux x86-64 syscall stubs.
; Linux syscall ABI:
;   syscall number → rax
;   args           → rdi, rsi, rdx, r10, r8, r9
;   return value   → rax  (negative = errno negated)
;   clobbered      → rcx, r11
;
; We use NASM syntax.  Assemble with:  nasm -f elf64
; ─────────────────────────────────────────────────────────────────────────────

%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_CLOSE       3
%define SYS_EXIT        60
%define SYS_SOCKET      41
%define SYS_ACCEPT      43
%define SYS_BIND        49
%define SYS_LISTEN      50
%define SYS_FCNTL       72
%define SYS_EXIT_GROUP  231

section .text

; ─── vision_syscall1(nr, a1) ──────────────────────────────────────────────
global vision_syscall1
vision_syscall1:
    mov     rax, rdi
    mov     rdi, rsi
    syscall
    ret

; ─── vision_syscall2(nr, a1, a2) ─────────────────────────────────────────
global vision_syscall2
vision_syscall2:
    mov     rax, rdi
    mov     rdi, rsi
    mov     rsi, rdx
    syscall
    ret

; ─── vision_syscall3(nr, a1, a2, a3) ─────────────────────────────────────
global vision_syscall3
vision_syscall3:
    mov     rax, rdi
    mov     rdi, rsi
    mov     rsi, rdx
    mov     rdx, rcx
    syscall
    ret

; ─── vision_syscall4(nr, a1, a2, a3, a4) ─────────────────────────────────
; Note: 4th arg uses r10 in Linux ABI, not rcx (rcx is clobbered by syscall)
global vision_syscall4
vision_syscall4:
    mov     rax, rdi
    mov     rdi, rsi
    mov     rsi, rdx
    mov     rdx, rcx
    mov     r10, r8
    syscall
    ret

; ─── vision_exit(code) ───────────────────────────────────────────────────
global vision_exit
vision_exit:
    mov     rax, SYS_EXIT_GROUP
    ; rdi already has exit code from C calling convention
    syscall
    ; should never reach here
    hlt

; ─── vision_memset(dst, val, n) ──────────────────────────────────────────
; Fast rep stosb — no libc
global vision_memset
vision_memset:
    push    rdi                 ; save dst for return value
    movzx   rax, sil            ; val (byte)
    mov     rcx, rdx            ; n
    rep     stosb
    pop     rax                 ; return dst
    ret

; ─── vision_memcpy(dst, src, n) ──────────────────────────────────────────
global vision_memcpy
vision_memcpy:
    push    rdi                 ; save dst
    mov     rcx, rdx            ; n
    rep     movsb               ; rdi=dst, rsi=src
    pop     rax
    ret

; ─── vision_memcmp(a, b, n) ──────────────────────────────────────────────
global vision_memcmp
vision_memcmp:
    xor     eax, eax
    test    rdx, rdx
    jz      .done
    mov     rcx, rdx
    repe    cmpsb               ; rdi=a, rsi=b
    je      .done
    movzx   eax, byte [rdi - 1]
    movzx   ecx, byte [rsi - 1]
    sub     eax, ecx
.done:
    ret
