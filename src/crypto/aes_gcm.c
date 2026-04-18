/*
 * src/crypto/aes_gcm.c
 * AES-128-GCM and AES-256-GCM AEAD.
 *
 * Builds on top of AES-NI assembly stubs (aesni.asm) and CLMUL GHASH.
 * Falls back to a constant-time pure-C AES when AES-NI is absent.
 *
 * Interface matches the TLS 1.3 record layer expectations:
 *   - 12-byte nonce (4-byte implicit + 8-byte explicit in TLS 1.3)
 *   - Additional authenticated data (AAD) for the TLS record header
 *   - 16-byte authentication tag
 */
#include "aes_gcm.h"
#include "vision/platform.h"

/* ── ASM stubs from aesni.asm (linked when VISION_ARCH_X86_64) ────────── */
#if defined(VISION_ARCH_X86_64)
extern void vision_aes128_keyschedule(const u8 key[16], u8 rk[176]);
extern void vision_aes256_keyschedule(const u8 key[32], u8 rk[240]);
extern void vision_aes128_encrypt_block(const u8 rk[176], const u8 in[16], u8 out[16]);
extern void vision_aes256_encrypt_block(const u8 rk[240], const u8 in[16], u8 out[16]);
extern void vision_clmul_ghash_block(u8 tag[16], const u8 h[16], const u8 data[16]);
#endif

/* ── Forward decls for fallback pure-C path ──────────────────────────── */
static void aes_encrypt_block_sw(const VisionAesGcmCtx* ctx,
                                  const u8 in[16], u8 out[16]);

/* ── Context init ────────────────────────────────────────────────────── */
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
    /* pure-C key schedule — implemented in aes_gcm_sw.c (sprint 2) */
    return -3;
#endif

    /* Derive H = AES_K(0^128) — the GHASH subkey */
    u8 zero[16];
    vision_memset(zero, 0, 16);
    vision_aesgcm_encrypt_block(ctx, zero, ctx->h_subkey);

    return 0;
}

/* ── Raw block encrypt (dispatches to HW or SW) ─────────────────────── */
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

/* ── GHASH over a buffer (pads last block to 16 bytes) ──────────────── */
static void ghash(const VisionAesGcmCtx* ctx,
                  const u8* data, usize len, u8 tag[16]) {
    while (len >= 16) {
#if defined(VISION_ARCH_X86_64)
        vision_clmul_ghash_block(tag, ctx->h_subkey, data);
#else
        /* SW GHASH fallback — sprint 2 */
        (void)ctx;
#endif
        data += 16;
        len  -= 16;
    }
    if (len > 0) {
        /* Pad final partial block with zeros */
        u8 padded[16];
        vision_memset(padded, 0, 16);
        vision_memcpy(padded, data, len);
#if defined(VISION_ARCH_X86_64)
        vision_clmul_ghash_block(tag, ctx->h_subkey, padded);
#endif
    }
}

/* ── CTR32 keystream increment ──────────────────────────────────────── */
static VISION_INLINE void ctr_increment(u8 ctr[16]) {
    /* Increment the low 32-bit counter (big-endian, bytes 12-15) */
    for (i32 i = 15; i >= 12; i--) {
        if (++ctr[i]) break;
    }
}

/* ── Seal (encrypt + authenticate) ─────────────────────────────────── */
i32 vision_aesgcm_seal(VisionAesGcmCtx* ctx,
                        const u8*  nonce,    /* 12 bytes */
                        const u8*  aad,      usize aad_len,
                        const u8*  plaintext, usize pt_len,
                        u8*        ciphertext,           /* pt_len bytes out */
                        u8         tag_out[16]) {
    /* J0 = nonce || 0x00000001 */
    u8 j0[16];
    vision_memcpy(j0, nonce, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

    /* Increment counter to 2 for data encryption (J0+1) */
    u8 ctr[16];
    vision_memcpy(ctr, j0, 16);
    ctr_increment(ctr);   /* CTR starts at J0 + 1 */

    /* Encrypt plaintext in 16-byte blocks (CTR mode) */
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

    /* GHASH(H, AAD || ciphertext) */
    u8 ghash_tag[16];
    vision_memset(ghash_tag, 0, 16);
    ghash(ctx, aad, aad_len, ghash_tag);
    ghash(ctx, ciphertext, pt_len, ghash_tag);

    /* Length block: len(AAD) || len(CT) in bits, big-endian 64-bit each */
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

    /* Tag = GHASH_result XOR AES_K(J0) */
    u8 s[16];
    vision_aesgcm_encrypt_block(ctx, j0, s);
    for (i32 i = 0; i < 16; i++) tag_out[i] = ghash_tag[i] ^ s[i];

    return 0;
}

/* ── Open (decrypt + verify) ────────────────────────────────────────── */
i32 vision_aesgcm_open(VisionAesGcmCtx* ctx,
                        const u8*  nonce,
                        const u8*  aad,      usize aad_len,
                        const u8*  ciphertext, usize ct_len,
                        const u8   tag_in[16],
                        u8*        plaintext) {
    /* Recompute expected tag */
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

    /* Constant-time tag comparison — no early exit */
    u8 diff = 0;
    for (i32 i = 0; i < 16; i++) diff |= (ghash_tag[i] ^ s[i]) ^ tag_in[i];
    if (diff != 0) return -1;   /* authentication failure */

    /* Tag verified — decrypt */
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

/* ── SW fallback stub (sprint 2) ────────────────────────────────────── */
static void aes_encrypt_block_sw(const VisionAesGcmCtx* ctx,
                                  const u8 in[16], u8 out[16]) {
    /* TODO: portable constant-time AES — no AES-NI */
    (void)ctx; (void)in; (void)out;
}
