/*
 * src/crypto/chacha20.c
 * ChaCha20-Poly1305 AEAD (RFC 8439).
 * Pure C — runs on any platform, no SIMD required.
 * Used as the fallback cipher suite when AES-NI is absent,
 * and as the preferred suite on ARM64.
 */
#include "chacha20.h"
#include "vision/platform.h"

/* ── ChaCha20 quarter-round ─────────────────────────────────────────── */
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)          \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7)

static VISION_INLINE u32 load_le32(const u8* p) {
    return (u32)p[0] | ((u32)p[1] << 8) |
           ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
static VISION_INLINE void store_le32(u8* p, u32 v) {
    p[0] = (u8)v; p[1] = (u8)(v>>8);
    p[2] = (u8)(v>>16); p[3] = (u8)(v>>24);
}

/*
 * ChaCha20 block function — produces 64 bytes of keystream.
 * key: 32 bytes, nonce: 12 bytes, counter: 32-bit block counter.
 */
static void chacha20_block(const u8 key[32], const u8 nonce[12],
                            u32 counter, u8 out[64]) {
    /* Constants: "expand 32-byte k" */
    u32 s[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        load_le32(key),      load_le32(key+4),
        load_le32(key+8),    load_le32(key+12),
        load_le32(key+16),   load_le32(key+20),
        load_le32(key+24),   load_le32(key+28),
        counter,
        load_le32(nonce),    load_le32(nonce+4), load_le32(nonce+8)
    };

    u32 x[16];
    vision_memcpy(x, s, 64);

    /* 20 rounds = 10 double-rounds */
    for (i32 i = 0; i < 10; i++) {
        /* Column rounds */
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    for (i32 i = 0; i < 16; i++) store_le32(out + i*4, x[i] + s[i]);
}

/* ── XOR plaintext/ciphertext with ChaCha20 keystream ──────────────── */
static void chacha20_xor(const u8 key[32], const u8 nonce[12],
                          u32 start_counter,
                          const u8* in, u8* out, usize len) {
    u32 ctr = start_counter;
    while (len >= 64) {
        u8 ks[64];
        chacha20_block(key, nonce, ctr++, ks);
        for (i32 i = 0; i < 64; i++) out[i] = in[i] ^ ks[i];
        in += 64; out += 64; len -= 64;
    }
    if (len > 0) {
        u8 ks[64];
        chacha20_block(key, nonce, ctr, ks);
        for (usize i = 0; i < len; i++) out[i] = in[i] ^ ks[i];
    }
}

/* ── Poly1305 MAC ───────────────────────────────────────────────────── */
/*
 * Poly1305 in 130-bit arithmetic.
 * We represent the accumulator as five 26-bit limbs to avoid
 * 128-bit overflow on 64-bit platforms.
 */
typedef struct {
    u32 r[5];   /* clamped key r (130-bit limbs) */
    u32 s[4];   /* finalization key s            */
    u32 h[5];   /* accumulator                   */
} Poly1305Ctx;

static void poly1305_init(Poly1305Ctx* ctx, const u8 key[32]) {
    /* Clamp r: clear specific bits per RFC 8439 §2.5 */
    u32 t[4];
    for (i32 i = 0; i < 4; i++) t[i] = load_le32(key + i*4);

    ctx->r[0] = ( t[0]                    ) & 0x3ffffffu;
    ctx->r[1] = ((t[0] >> 26) | (t[1] << 6)) & 0x3ffff03u;
    ctx->r[2] = ((t[1] >> 20) | (t[2] << 12)) & 0x3ffc0ffu;
    ctx->r[3] = ((t[2] >> 14) | (t[3] << 18)) & 0x3f03fffu;
    ctx->r[4] = ( t[3] >> 8  )                & 0x00fffffu;

    for (i32 i = 0; i < 4; i++) ctx->s[i] = load_le32(key + 16 + i*4);
    for (i32 i = 0; i < 5; i++) ctx->h[i] = 0;
}

static void poly1305_block(Poly1305Ctx* ctx, const u8* m, u32 final_bit) {
    /* Load message block as 130-bit number (with high bit) */
    u32 t[4];
    for (i32 i = 0; i < 4; i++) t[i] = load_le32(m + i*4);

    u32 d[5];
    d[0] = ( t[0]                     ) & 0x3ffffffu;
    d[1] = ((t[0] >> 26) | (t[1] <<  6)) & 0x3ffffffu;
    d[2] = ((t[1] >> 20) | (t[2] << 12)) & 0x3ffffffu;
    d[3] = ((t[2] >> 14) | (t[3] << 18)) & 0x3ffffffu;
    d[4] = ( t[3] >>  8) | (final_bit << 24);

    /* h += m */
    for (i32 i = 0; i < 5; i++) ctx->h[i] += d[i];

    /* h *= r  (mod 2^130-5) using 64-bit intermediates */
    u32* r = ctx->r;
    u64  tp0, tp1, tp2, tp3, tp4;
    u64  h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2],
         h3 = ctx->h[3], h4 = ctx->h[4];

    tp0 = h0*r[0] + h1*(5*r[4]) + h2*(5*r[3]) + h3*(5*r[2]) + h4*(5*r[1]);
    tp1 = h0*r[1] + h1*r[0]     + h2*(5*r[4]) + h3*(5*r[3]) + h4*(5*r[2]);
    tp2 = h0*r[2] + h1*r[1]     + h2*r[0]     + h3*(5*r[4]) + h4*(5*r[3]);
    tp3 = h0*r[3] + h1*r[2]     + h2*r[1]     + h3*r[0]     + h4*(5*r[4]);
    tp4 = h0*r[4] + h1*r[3]     + h2*r[2]     + h3*r[1]     + h4*r[0];

    /* Propagate carry bits */
    tp1 += tp0 >> 26; ctx->h[0] = (u32)(tp0 & 0x3ffffffu);
    tp2 += tp1 >> 26; ctx->h[1] = (u32)(tp1 & 0x3ffffffu);
    tp3 += tp2 >> 26; ctx->h[2] = (u32)(tp2 & 0x3ffffffu);
    tp4 += tp3 >> 26; ctx->h[3] = (u32)(tp3 & 0x3ffffffu);
    ctx->h[0] += (u32)(tp4 >> 26) * 5;
    ctx->h[4]  = (u32)(tp4 & 0x3ffffffu);
    ctx->h[1] += ctx->h[0] >> 26;
    ctx->h[0] &= 0x3ffffffu;
}

static void poly1305_update(Poly1305Ctx* ctx, const u8* data, usize len) {
    while (len >= 16) {
        poly1305_block(ctx, data, 1);
        data += 16; len -= 16;
    }
    if (len > 0) {
        u8 pad[16];
        vision_memset(pad, 0, 16);
        vision_memcpy(pad, data, len);
        pad[len] = 1;  /* final block padding bit already included */
        /* For the final partial block, final_bit=0 (bit already in pad) */
        poly1305_block(ctx, pad, 0);
    }
}

static void poly1305_finish(Poly1305Ctx* ctx, u8 tag[16]) {
    /* Reduce h mod 2^130-5 */
    u32 h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2],
        h3 = ctx->h[3], h4 = ctx->h[4];

    u32 c = h1 >> 26; h1 &= 0x3ffffffu;
           h2 += c; c = h2 >> 26; h2 &= 0x3ffffffu;
           h3 += c; c = h3 >> 26; h3 &= 0x3ffffffu;
           h4 += c; c = h4 >> 26; h4 &= 0x3ffffffu;
           h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffffu;
           h1 += c;

    /* Compute h - p (where p = 2^130-5) to check if h >= p */
    u32 g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffffu;
    u32 g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffffu;
    u32 g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffffu;
    u32 g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffffu;
    u32 g4 = h4 + c - (1u << 26);

    /* Select h if h < p, else g (constant-time select) */
    u32 mask = (g4 >> 31) - 1u;   /* all-ones if g4 MSB set (h >= p) */
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    /* Pack h into 128-bit little-endian */
    u64 f0 = ((u64)h0 | ((u64)h1 << 26)) + (u64)ctx->s[0];
    u64 f1 = ((u64)(h1 >> 6) | ((u64)h2 << 20)) + (u64)ctx->s[1] + (f0 >> 32);
    u64 f2 = ((u64)(h2 >> 12) | ((u64)h3 << 14)) + (u64)ctx->s[2] + (f1 >> 32);
    u64 f3 = ((u64)(h3 >> 18) | ((u64)h4 << 8)) + (u64)ctx->s[3] + (f2 >> 32);

    store_le32(tag,    (u32)f0);
    store_le32(tag+4,  (u32)f1);
    store_le32(tag+8,  (u32)f2);
    store_le32(tag+12, (u32)f3);
}

/* ── Poly1305 key generation from ChaCha20 block 0 ─────────────────── */
static void poly1305_keygen(const u8 key[32], const u8 nonce[12], u8 pkey[32]) {
    u8 block[64];
    chacha20_block(key, nonce, 0, block);
    vision_memcpy(pkey, block, 32);
}

/* ── AEAD seal ──────────────────────────────────────────────────────── */
i32 vision_chacha20poly1305_seal(
        const u8*  key,          /* 32 bytes */
        const u8*  nonce,        /* 12 bytes */
        const u8*  aad,   usize  aad_len,
        const u8*  pt,    usize  pt_len,
        u8*        ct,
        u8         tag[16]) {

    /* Encrypt: counter starts at 1 (block 0 reserved for Poly1305 key) */
    chacha20_xor(key, nonce, 1, pt, ct, pt_len);

    /* MAC key from block 0 */
    u8 mac_key[32];
    poly1305_keygen(key, nonce, mac_key);

    /* Poly1305 over: AAD || pad(AAD) || CT || pad(CT) || len(AAD) || len(CT) */
    Poly1305Ctx pctx;
    poly1305_init(&pctx, mac_key);

    /* AAD with 16-byte block padding */
    poly1305_update(&pctx, aad, aad_len);
    if (aad_len % 16) {
        u8 pad[16]; vision_memset(pad, 0, 16);
        poly1305_update(&pctx, pad, 16 - (aad_len % 16));
    }
    /* Ciphertext with padding */
    poly1305_update(&pctx, ct, pt_len);
    if (pt_len % 16) {
        u8 pad[16]; vision_memset(pad, 0, 16);
        poly1305_update(&pctx, pad, 16 - (pt_len % 16));
    }
    /* Lengths (little-endian 64-bit) */
    u8 lengths[16];
    u64 al = aad_len, cl = pt_len;
    for (i32 i = 0; i < 8; i++) { lengths[i]   = (u8)al; al >>= 8; }
    for (i32 i = 0; i < 8; i++) { lengths[8+i] = (u8)cl; cl >>= 8; }
    poly1305_update(&pctx, lengths, 16);

    poly1305_finish(&pctx, tag);
    return 0;
}

/* ── AEAD open ──────────────────────────────────────────────────────── */
i32 vision_chacha20poly1305_open(
        const u8*  key,
        const u8*  nonce,
        const u8*  aad,   usize  aad_len,
        const u8*  ct,    usize  ct_len,
        const u8   tag[16],
        u8*        pt) {

    /* Recompute tag */
    u8 mac_key[32];
    poly1305_keygen(key, nonce, mac_key);

    Poly1305Ctx pctx;
    poly1305_init(&pctx, mac_key);
    poly1305_update(&pctx, aad, aad_len);
    if (aad_len % 16) {
        u8 pad[16]; vision_memset(pad, 0, 16);
        poly1305_update(&pctx, pad, 16 - (aad_len % 16));
    }
    poly1305_update(&pctx, ct, ct_len);
    if (ct_len % 16) {
        u8 pad[16]; vision_memset(pad, 0, 16);
        poly1305_update(&pctx, pad, 16 - (ct_len % 16));
    }
    u8 lengths[16];
    u64 al = aad_len, cl = ct_len;
    for (i32 i = 0; i < 8; i++) { lengths[i]   = (u8)al; al >>= 8; }
    for (i32 i = 0; i < 8; i++) { lengths[8+i] = (u8)cl; cl >>= 8; }
    poly1305_update(&pctx, lengths, 16);

    u8 expected[16];
    poly1305_finish(&pctx, expected);

    /* Constant-time comparison */
    u8 diff = 0;
    for (i32 i = 0; i < 16; i++) diff |= expected[i] ^ tag[i];
    if (diff != 0) return -1;

    chacha20_xor(key, nonce, 1, ct, pt, ct_len);
    return 0;
}
