%define AES128_ROUNDS  10
%define AES256_ROUNDS  14

section .text

global vision_aes128_keyschedule
vision_aes128_keyschedule:
    movdqu  xmm1, [rdi]
    movdqu  [rsi], xmm1
    add     rsi, 16

%macro EXPAND128 1              ; arg = RCON imm8
    aeskeygenassist xmm2, xmm1, %1
    pshufd          xmm2, xmm2, 0xff
    vpslldq         xmm3, xmm1, 4
    pxor            xmm1, xmm3
    vpslldq         xmm3, xmm1, 4
    pxor            xmm1, xmm3
    vpslldq         xmm3, xmm1, 4
    pxor            xmm1, xmm3
    pxor            xmm1, xmm2
    movdqu          [rsi], xmm1
    add             rsi, 16
%endmacro

    EXPAND128 0x01
    EXPAND128 0x02
    EXPAND128 0x04
    EXPAND128 0x08
    EXPAND128 0x10
    EXPAND128 0x20
    EXPAND128 0x40
    EXPAND128 0x80
    EXPAND128 0x1b
    EXPAND128 0x36
    ret

global vision_aes128_encrypt_block
vision_aes128_encrypt_block:
    movdqu  xmm0, [rsi]
    movdqu  xmm1, [rdi]
    pxor    xmm0, xmm1

%assign rnd 1
%rep 9
    movdqu  xmm1, [rdi + rnd * 16]
    aesenc  xmm0, xmm1
    %assign rnd rnd+1
%endrep

    movdqu  xmm1, [rdi + 160]
    aesenclast xmm0, xmm1

    movdqu  [rdx], xmm0
    ret

global vision_aes256_keyschedule
vision_aes256_keyschedule:
    movdqu  xmm1, [rdi]
    movdqu  xmm3, [rdi + 16]
    movdqu  [rsi],      xmm1
    movdqu  [rsi + 16], xmm3
    add     rsi, 32

%macro EXPAND256_A 1           ; generate odd round keys from xmm1+xmm3
    aeskeygenassist xmm2, xmm3, %1
    pshufd          xmm2, xmm2, 0xff
    vpslldq         xmm4, xmm1, 4
    pxor            xmm1, xmm4
    vpslldq         xmm4, xmm1, 4
    pxor            xmm1, xmm4
    vpslldq         xmm4, xmm1, 4
    pxor            xmm1, xmm4
    pxor            xmm1, xmm2
    movdqu          [rsi], xmm1
    add             rsi, 16
%endmacro

%macro EXPAND256_B 0           ; generate even round keys from updated xmm1+xmm3
    aeskeygenassist xmm2, xmm1, 0x00
    pshufd          xmm2, xmm2, 0xaa
    vpslldq         xmm4, xmm3, 4
    pxor            xmm3, xmm4
    vpslldq         xmm4, xmm3, 4
    pxor            xmm3, xmm4
    vpslldq         xmm4, xmm3, 4
    pxor            xmm3, xmm4
    pxor            xmm3, xmm2
    movdqu          [rsi], xmm3
    add             rsi, 16
%endmacro

    EXPAND256_A 0x01 ; rk[2]
    EXPAND256_B      ; rk[3]
    EXPAND256_A 0x02 ; rk[4]
    EXPAND256_B      ; rk[5]
    EXPAND256_A 0x04 ; rk[6]
    EXPAND256_B      ; rk[7]
    EXPAND256_A 0x08 ; rk[8]
    EXPAND256_B      ; rk[9]
    EXPAND256_A 0x10 ; rk[10]
    EXPAND256_B      ; rk[11]
    EXPAND256_A 0x20 ; rk[12]
    EXPAND256_B      ; rk[13]
    EXPAND256_A 0x40 ; rk[14] — final, no B needed for AES-256
    ret

global vision_aes256_encrypt_block
vision_aes256_encrypt_block:
    movdqu  xmm0, [rsi]
    movdqu  xmm1, [rdi]
    pxor    xmm0, xmm1

%assign rnd 1
%rep 13
    movdqu  xmm1, [rdi + rnd * 16]
    aesenc  xmm0, xmm1
    %assign rnd rnd+1
%endrep

    movdqu  xmm1, [rdi + 224]
    aesenclast xmm0, xmm1
    movdqu  [rdx], xmm0
    ret

global vision_clmul_ghash_block
vision_clmul_ghash_block:
    movdqu  xmm0, [rdi]         ; current tag
    movdqu  xmm1, [rsi]         ; H subkey
    movdqu  xmm2, [rdx]         ; data block

    ; XOR data into tag first (GHASH accumulation)
    pxor    xmm0, xmm2

    ; Carry-less multiply: xmm0 × H in GF(2^128) using PCLMULQDQ
    ; Full 256-bit product needs 3 multiplications (Karatsuba reduction)
    movdqa  xmm3, xmm0
    movdqa  xmm4, xmm0

    pclmulqdq xmm0, xmm1, 0x00  ; lo × lo
    pclmulqdq xmm4, xmm1, 0x11  ; hi × hi
    pclmulqdq xmm3, xmm1, 0x10  ; lo × hi
    movdqa  xmm5, xmm3
    pclmulqdq xmm5, xmm1, 0x01  ; hi × lo
    pxor    xmm3, xmm5           ; middle term

    ; Combine 256-bit product
    movdqa  xmm5, xmm3
    pslldq  xmm3, 8
    psrldq  xmm5, 8
    pxor    xmm0, xmm3
    pxor    xmm4, xmm5

    ; Reduction modulo x^128 + x^7 + x^2 + x + 1 (GCM polynomial)
    movdqa  xmm5, xmm0
    movdqa  xmm6, xmm0
    movdqa  xmm7, xmm0
    pslld   xmm5, 31
    pslld   xmm6, 30
    pslld   xmm7, 25
    pxor    xmm5, xmm6
    pxor    xmm5, xmm7
    movdqa  xmm6, xmm5
    pslldq  xmm5, 12
    psrldq  xmm6, 4
    pxor    xmm0, xmm5

    movdqa  xmm5, xmm0
    movdqa  xmm7, xmm0
    movdqa  xmm8, xmm0
    psrld   xmm5, 1
    psrld   xmm7, 2
    psrld   xmm8, 7
    pxor    xmm5, xmm7
    pxor    xmm5, xmm8
    pxor    xmm5, xmm6
    pxor    xmm0, xmm5
    pxor    xmm0, xmm4

    movdqu  [rdi], xmm0          ; write back updated tag
    ret
