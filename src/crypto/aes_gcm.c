#include "aes_gcm.h"
#include "vision/platform.h"

#if defined(VISION_ARCH_X86_64)
extern void vision_aes128_keyschedule(const u8 key[16], u8 rk[176]);
extern void vision_aes256_keyschedule(const u8 key[32], u8 rk[240]);
extern void vision_aes128_encrypt_block(const u8 rk[176], const u8 in[16], u8 out[16]);
extern void vision_aes256_encrypt_block(const u8 rk[240], const u8 in[16], u8 out[16]);
extern void vision_clmul_ghash_block(u8 tag[16], const u8 h[16], const u8 data[16]);
#endif

static void aes_encrypt_block_sw(const VisionAesGcmCtx* ctx,
                                  const u8 in[16], u8 out[16]);

i32 vision_aesgcm_init(VisionAesGcmCtx* ctx, const u8* key, usize key_len) {
    if (!ctx || !key) return -1;
    if (key_len != 16 && key_len != 32) return -2;

    ctx->key_len = (u32)key_len;
    vision_memcpy(ctx->key, key, key_len);

#if defined(VISION_ARCH_X86_64)
    if (key_len == 16)
        vision_aes128_keyschedule(key, ctx->round_keys);
    else
        vision_aes256_keyschedule(key, ctx->round_keys);
#else
    aes_keyschedule_sw(key, (u32)key_len, ctx->round_keys);
#endif

    u8 zero[16];
    vision_memset(zero, 0, 16);
    vision_aesgcm_encrypt_block(ctx, zero, ctx->h_subkey);

    return 0;
}

void vision_aesgcm_encrypt_block(const VisionAesGcmCtx* ctx,
                                  const u8 in[16], u8 out[16]) {
#if defined(VISION_ARCH_X86_64)
    if (ctx->key_len == 16)
        vision_aes128_encrypt_block(ctx->round_keys, in, out);
    else
        vision_aes256_encrypt_block(ctx->round_keys, in, out);
#else
    aes_encrypt_block_sw(ctx, in, out);
#endif
}

static void ghash(const VisionAesGcmCtx* ctx,
                  const u8* data, usize len, u8 tag[16]) {
    while (len >= 16) {
#if defined(VISION_ARCH_X86_64)
        vision_clmul_ghash_block(tag, ctx->h_subkey, data);
#else
        (void)ctx;
#endif
        data += 16;
        len  -= 16;
    }
    if (len > 0) {
        u8 padded[16];
        vision_memset(padded, 0, 16);
        vision_memcpy(padded, data, len);
#if defined(VISION_ARCH_X86_64)
        vision_clmul_ghash_block(tag, ctx->h_subkey, padded);
#endif
    }
}

static VISION_INLINE void ctr_increment(u8 ctr[16]) {
    for (i32 i = 15; i >= 12; i--) {
        if (++ctr[i]) break;
    }
}

i32 vision_aesgcm_seal(VisionAesGcmCtx* ctx,
                        const u8*  nonce,
                        const u8*  aad,      usize aad_len,
                        const u8*  plaintext, usize pt_len,
                        u8*        ciphertext,
                        u8         tag_out[16]) {
    u8 j0[16];
    vision_memcpy(j0, nonce, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

    u8 ctr[16];
    vision_memcpy(ctr, j0, 16);
    ctr_increment(ctr);

    usize remaining = pt_len;
    const u8* in  = plaintext;
    u8*       out = ciphertext;

    while (remaining >= 16) {
        u8 keystream[16];
        vision_aesgcm_encrypt_block(ctx, ctr, keystream);
        for (i32 i = 0; i < 16; i++) out[i] = in[i] ^ keystream[i];
        ctr_increment(ctr);
        in  += 16; out += 16; remaining -= 16;
    }
    if (remaining > 0) {
        u8 keystream[16];
        vision_aesgcm_encrypt_block(ctx, ctr, keystream);
        for (usize i = 0; i < remaining; i++) out[i] = in[i] ^ keystream[i];
    }

    u8 ghash_tag[16];
    vision_memset(ghash_tag, 0, 16);
    ghash(ctx, aad, aad_len, ghash_tag);
    ghash(ctx, ciphertext, pt_len, ghash_tag);

    u8 len_block[16];
    vision_memset(len_block, 0, 16);
    u64 aad_bits = aad_len * 8;
    u64 ct_bits  = pt_len  * 8;
    for (i32 i = 7; i >= 0; i--) {
        len_block[i]     = (u8)(aad_bits); aad_bits >>= 8;
        len_block[i + 8] = (u8)(ct_bits);  ct_bits  >>= 8;
    }
#if defined(VISION_ARCH_X86_64)
    vision_clmul_ghash_block(ghash_tag, ctx->h_subkey, len_block);
#endif

    u8 s[16];
    vision_aesgcm_encrypt_block(ctx, j0, s);
    for (i32 i = 0; i < 16; i++) tag_out[i] = ghash_tag[i] ^ s[i];

    return 0;
}

i32 vision_aesgcm_open(VisionAesGcmCtx* ctx,
                        const u8*  nonce,
                        const u8*  aad,      usize aad_len,
                        const u8*  ciphertext, usize ct_len,
                        const u8   tag_in[16],
                        u8*        plaintext) {
    u8 j0[16];
    vision_memcpy(j0, nonce, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

    u8 ghash_tag[16];
    vision_memset(ghash_tag, 0, 16);
    ghash(ctx, aad, aad_len, ghash_tag);
    ghash(ctx, ciphertext, ct_len, ghash_tag);

    u8 len_block[16];
    vision_memset(len_block, 0, 16);
    u64 aad_bits = aad_len * 8;
    u64 ct_bits  = ct_len  * 8;
    for (i32 i = 7; i >= 0; i--) {
        len_block[i]     = (u8)(aad_bits); aad_bits >>= 8;
        len_block[i + 8] = (u8)(ct_bits);  ct_bits  >>= 8;
    }
#if defined(VISION_ARCH_X86_64)
    vision_clmul_ghash_block(ghash_tag, ctx->h_subkey, len_block);
#endif

    u8 s[16];
    vision_aesgcm_encrypt_block(ctx, j0, s);

    u8 diff = 0;
    for (i32 i = 0; i < 16; i++) diff |= (ghash_tag[i] ^ s[i]) ^ tag_in[i];
    if (diff != 0) return -1;

    u8 ctr[16];
    vision_memcpy(ctr, j0, 16);
    ctr_increment(ctr);

    usize remaining = ct_len;
    const u8* in = ciphertext;
    u8*       out = plaintext;
    while (remaining >= 16) {
        u8 ks[16];
        vision_aesgcm_encrypt_block(ctx, ctr, ks);
        for (i32 i = 0; i < 16; i++) out[i] = in[i] ^ ks[i];
        ctr_increment(ctr);
        in += 16; out += 16; remaining -= 16;
    }
    if (remaining > 0) {
        u8 ks[16];
        vision_aesgcm_encrypt_block(ctx, ctr, ks);
        for (usize i = 0; i < remaining; i++) out[i] = in[i] ^ ks[i];
    }
    return 0;
}

static const u8 AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const u8 RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static VISION_INLINE u8 xtime(u8 x) {
    return (u8)((x << 1) ^ ((x >> 7) * 0x1b));
}

static VISION_INLINE u8 sub_byte(u8 x) { return AES_SBOX[x]; }

static VISION_INLINE u32 sub_word(u32 w) {
    return ((u32)sub_byte((u8)(w >> 24)) << 24) |
           ((u32)sub_byte((u8)(w >> 16)) << 16) |
           ((u32)sub_byte((u8)(w >>  8)) <<  8) |
           ((u32)sub_byte((u8)(w      ))      );
}

static VISION_INLINE u32 rot_word(u32 w) { return (w << 8) | (w >> 24); }

static void aes_keyschedule_sw(const u8* key, u32 key_len, u8* round_keys) {
    u32 Nk = key_len / 4;
    u32 Nr = (Nk == 4) ? 10 : 14;
    u32* w = (u32*)round_keys;
    u32 i;
    for (i = 0; i < Nk; i++) {
        w[i] = ((u32)key[4*i] << 24) | ((u32)key[4*i+1] << 16) |
               ((u32)key[4*i+2] << 8) | (u32)key[4*i+3];
    }
    for (i = Nk; i < 4 * (Nr + 1); i++) {
        u32 temp = w[i - 1];
        if (i % Nk == 0) {
            temp = sub_word(rot_word(temp)) ^ ((u32)RCON[i / Nk] << 24);
        } else if (Nk > 6 && (i % Nk == 4)) {
            temp = sub_word(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }
}

static void mix_columns(u8 state[16]) {
    for (u32 i = 0; i < 4; i++) {
        u32 col = i * 4;
        u8 s0 = state[col], s1 = state[col + 1], s2 = state[col + 2], s3 = state[col + 3];
        u8 t = s0 ^ s1 ^ s2 ^ s3, u = s0;
        state[col]     = xtime(s0 ^ s1) ^ s1 ^ s2 ^ s3 ^ t;
        state[col + 1] = xtime(s1 ^ s2) ^ s2 ^ s3 ^ s0 ^ t;
        state[col + 2] = xtime(s2 ^ s3) ^ s3 ^ s0 ^ s1 ^ t;
        state[col + 3] = xtime(s3 ^ u)  ^ u  ^ s1 ^ s2 ^ t;
    }
}

static void shift_rows(u8 state[16]) {
    u8 tmp = state[1];
    state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[15];
    state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = tmp;
}

static void add_round_key(u8 state[16], const u8* round_key) {
    for (u32 i = 0; i < 16; i++) state[i] ^= round_key[i];
}

static void sub_bytes(u8 state[16]) {
    for (u32 i = 0; i < 16; i++) state[i] = sub_byte(state[i]);
}

static void aes_enc_round_sw(u8 state[16], const u8* round_key) {
    sub_bytes(state); shift_rows(state); mix_columns(state); add_round_key(state, round_key);
}

static void aes_enc_final_round_sw(u8 state[16], const u8* round_key) {
    sub_bytes(state); shift_rows(state); add_round_key(state, round_key);
}

static void aes_encrypt_block_sw(const VisionAesGcmCtx* ctx, const u8 in[16], u8 out[16]) {
    u8 state[16];
    u32 Nr = (ctx->key_len == 16) ? 10 : 14;
    vision_memcpy(state, in, 16);
    add_round_key(state, ctx->round_keys);
    for (u32 round = 1; round < Nr; round++) aes_enc_round_sw(state, ctx->round_keys + round * 16);
    aes_enc_final_round_sw(state, ctx->round_keys + Nr * 16);
    vision_memcpy(out, state, 16);
}
