/* platform/macos/syscall.S
 * macOS x86-64 BSD syscall stubs.
 * macOS syscall ABI:
 *   number = Linux_nr | 0x2000000
 *   args   = rdi, rsi, rdx, r10, r8, r9
 *   return = rax (carry flag set on error)
 */

#define SYS_EXIT      0x2000001
#define SYS_READ      0x2000003
#define SYS_WRITE     0x2000004
#define SYS_CLOSE     0x2000006
#define SYS_SOCKET    0x2000061
#define SYS_BIND      0x2000068
#define SYS_LISTEN    0x2000069
#define SYS_ACCEPT    0x200001E
#define SYS_FCNTL     0x200005C

.text

.globl _vision_syscall3
_vision_syscall3:
    movq    %rdi, %rax
    movq    %rsi, %rdi
    movq    %rdx, %rsi
    movq    %rcx, %rdx
    syscall
    ret

.globl _vision_syscall4
_vision_syscall4:
    movq    %rdi, %rax
    movq    %rsi, %rdi
    movq    %rdx, %rsi
    movq    %rcx, %rdx
    movq    %r8,  %r10
    syscall
    ret

.globl _vision_exit
_vision_exit:
    movq    $SYS_EXIT, %rax
    syscall
    hlt

.globl _vision_memset
_vision_memset:
    pushq   %rdi
    movzbl  %sil, %eax
    movq    %rdx, %rcx
    rep     stosb
    popq    %rax
    ret

.globl _vision_memcpy
_vision_memcpy:
    pushq   %rdi
    movq    %rdx, %rcx
    rep     movsb
    popq    %rax
    ret

.globl _vision_memcmp
_vision_memcmp:
    xorl    %eax, %eax
    testq   %rdx, %rdx
    jz      .Ldone
    movq    %rdx, %rcx
    repe    cmpsb
    je      .Ldone
    movzbl  -1(%rdi), %eax
    movzbl  -1(%rsi), %ecx
    subl    %ecx, %eax
.Ldone:
    ret
