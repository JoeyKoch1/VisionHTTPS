/*
 * src/crypto/sha256.c
 * SHA-256 — FIPS 180-4 compliant, pure C, no libc.
 */
#include "sha256.h"
#include "vision/platform.h"

/* ── Round constants ────────────────────────────────────────────────────── */
static const u32 K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(e,f,g)    (((e) & (f)) ^ (~(e) & (g)))
#define MAJ(a,b,c)   (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define EP0(a)       (ROTR32(a,2)  ^ ROTR32(a,13) ^ ROTR32(a,22))
#define EP1(e)       (ROTR32(e,6)  ^ ROTR32(e,11) ^ ROTR32(e,25))
#define SIG0(x)      (ROTR32(x,7)  ^ ROTR32(x,18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))

static VISION_INLINE u32 load_be32(const u8* p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
           ((u32)p[2] <<  8) |  (u32)p[3];
}
static VISION_INLINE void store_be32(u8* p, u32 v) {
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16);
    p[2] = (u8)(v >>  8); p[3] = (u8)v;
}

static void sha256_compress(VisionSha256Ctx* ctx, const u8 block[64]) {
    u32 w[64];
    for (i32 i = 0; i < 16; i++) w[i] = load_be32(block + i * 4);
    for (i32 i = 16; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    u32 a = ctx->state[0], b = ctx->state[1], c = ctx->state[2],
        d = ctx->state[3], e = ctx->state[4], f = ctx->state[5],
        g = ctx->state[6], h = ctx->state[7];

    for (i32 i = 0; i < 64; i++) {
        u32 t1 = h + EP1(e) + CH(e,f,g) + K[i] + w[i];
        u32 t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
    ctx->state[3] += d; ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

void vision_sha256_init(VisionSha256Ctx* ctx) {
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
    ctx->bitcount = 0;
    ctx->buf_len  = 0;
}

void vision_sha256_update(VisionSha256Ctx* ctx, const u8* data, usize len) {
    ctx->bitcount += len * 8;
    while (len > 0) {
        usize space = VISION_SHA256_BLOCK_SIZE - ctx->buf_len;
        usize take  = (len < space) ? len : space;
        vision_memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += (u32)take;
        data += take;
        len  -= take;
        if (ctx->buf_len == VISION_SHA256_BLOCK_SIZE) {
            sha256_compress(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

void vision_sha256_final(VisionSha256Ctx* ctx, u8 out[VISION_SHA256_DIGEST_SIZE]) {
    u8 pad[VISION_SHA256_BLOCK_SIZE * 2];
    vision_memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    usize pad_len = (ctx->buf_len < 56)
        ? (56 - ctx->buf_len)
        : (64 + 56 - ctx->buf_len);

    u8 len_be[8];
    u64 bc = ctx->bitcount;
    for (i32 i = 7; i >= 0; i--) { len_be[i] = (u8)bc; bc >>= 8; }

    vision_sha256_update(ctx, pad, pad_len);
    vision_sha256_update(ctx, len_be, 8);

    for (i32 i = 0; i < 8; i++) store_be32(out + i * 4, ctx->state[i]);
}

void vision_sha256(const u8* data, usize len, u8 out[VISION_SHA256_DIGEST_SIZE]) {
    VisionSha256Ctx ctx;
    vision_sha256_init(&ctx);
    vision_sha256_update(&ctx, data, len);
    vision_sha256_final(&ctx, out);
}
