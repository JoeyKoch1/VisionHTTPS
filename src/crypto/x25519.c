/*
 * src/crypto/x25519.c
 * X25519 (Curve25519 ECDH) — RFC 7748.
 *
 * Arithmetic: GF(2^255-19) using five 51-bit limbs in u64.
 * Scalar multiplication: Montgomery ladder — constant-time, no branches on secret data.
 * No externs. No libc. No dynamic allocation.
 *
 * Reference: djb's original paper + RFC 7748 §5 test vectors.
 */
#include "x25519.h"
#include "vision/platform.h"

/* ── Field element: 5 × 51-bit limbs, little-endian ────────────────── */
typedef struct { u64 v[5]; } Fe;

/* p = 2^255 - 19 */
#define P0 0x7ffffffffffedULL
#define P1 0x7ffffffffffffULL
/* all limbs 1..4 are (2^51 - 1) except limb 0 which is (2^51 - 19) */

static const Fe ZERO = {{ 0, 0, 0, 0, 0 }};
static const Fe ONE  = {{ 1, 0, 0, 0, 0 }};

/* ── Load / store (little-endian 32 bytes ↔ 5×51-bit limbs) ────────── */
static Fe fe_load(const u8 b[32]) {
    /* Mask off top bit per RFC 7748 */
    u8 tmp[32];
    vision_memcpy(tmp, b, 32);
    tmp[31] &= 0x7f;

    u64 t[4];
    for (i32 i = 0; i < 4; i++) {
        t[i] = 0;
        for (i32 j = 0; j < 8; j++)
            t[i] |= (u64)tmp[i*8 + j] << (j * 8);
    }
    Fe r;
    r.v[0] =  t[0]        & 0x7ffffffffffffULL;
    r.v[1] = (t[0] >> 51  | t[1] << 13) & 0x7ffffffffffffULL;
    r.v[2] = (t[1] >> 38  | t[2] << 26) & 0x7ffffffffffffULL;
    r.v[3] = (t[2] >> 25  | t[3] << 39) & 0x7ffffffffffffULL;
    r.v[4] =  t[3] >> 12;
    return r;
}

static void fe_store(const Fe* a, u8 out[32]) {
    /* Fully reduce first */
    Fe r = *a;
    /* Carry propagation */
    for (i32 i = 0; i < 4; i++) {
        r.v[i+1] += r.v[i] >> 51;
        r.v[i]   &= 0x7ffffffffffffULL;
    }
    u64 carry = r.v[4] >> 51;
    r.v[4] &= 0x7ffffffffffffULL;
    r.v[0] += 19 * carry;
    for (i32 i = 0; i < 4; i++) {
        r.v[i+1] += r.v[i] >> 51;
        r.v[i]   &= 0x7ffffffffffffULL;
    }

    /* Pack 5×51 → 4×64 */
    u64 t[4];
    t[0] = r.v[0] | (r.v[1] << 51);
    t[1] = (r.v[1] >> 13) | (r.v[2] << 38);
    t[2] = (r.v[2] >> 26) | (r.v[3] << 25);
    t[3] = (r.v[3] >> 39) | (r.v[4] << 12);

    for (i32 i = 0; i < 4; i++)
        for (i32 j = 0; j < 8; j++)
            out[i*8 + j] = (u8)(t[i] >> (j*8));
}

/* ── Field arithmetic ───────────────────────────────────────────────── */
static VISION_INLINE Fe fe_add(const Fe* a, const Fe* b) {
    Fe r;
    for (i32 i = 0; i < 5; i++) r.v[i] = a->v[i] + b->v[i];
    return r;
}

static VISION_INLINE Fe fe_sub(const Fe* a, const Fe* b) {
    /* Add 2p before subtracting to stay positive */
    static const u64 two_p[5] = {
        0xFFFFFFFFFFFDA, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE
    };
    Fe r;
    for (i32 i = 0; i < 5; i++) r.v[i] = a->v[i] + two_p[i] - b->v[i];
    return r;
}

/* 128-bit multiply helper */
typedef struct { u64 lo, hi; } U128;
static VISION_INLINE U128 mul64(u64 a, u64 b) {
#if defined(__SIZEOF_INT128__)
    unsigned __int128 r = (unsigned __int128)a * b;
    return (U128){ (u64)r, (u64)(r >> 64) };
#else
    /* Portable 64×64→128 via 32-bit halves */
    u64 al = a & 0xffffffffULL, ah = a >> 32;
    u64 bl = b & 0xffffffffULL, bh = b >> 32;
    u64 p0 = al * bl, p1 = al * bh, p2 = ah * bl, p3 = ah * bh;
    u64 mid = (p0 >> 32) + (p1 & 0xffffffffULL) + (p2 & 0xffffffffULL);
    return (U128){
        (p0 & 0xffffffffULL) | (mid << 32),
        p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32)
    };
#endif
}

static Fe fe_mul(const Fe* a, const Fe* b) {
    /* Schoolbook with reduction: each ai*bj term, collect mod p */
    u64 a0=a->v[0], a1=a->v[1], a2=a->v[2], a3=a->v[3], a4=a->v[4];
    u64 b0=b->v[0], b1=b->v[1], b2=b->v[2], b3=b->v[3], b4=b->v[4];

    /* 19 * upper limbs (reduces mod 2^255-19) */
    u64 b1_19 = b1*19, b2_19 = b2*19, b3_19 = b3*19, b4_19 = b4*19;

    U128 t0, t1, t2, t3, t4;
    U128 tmp;

    #define ADDMUL(T, X, Y) do { tmp = mul64(X, Y); T.lo += tmp.lo; T.hi += tmp.hi + (T.lo < tmp.lo ? 1 : 0); } while(0)

    t0 = mul64(a0, b0);
    ADDMUL(t0, a1, b4_19);
    ADDMUL(t0, a2, b3_19);
    ADDMUL(t0, a3, b2_19);
    ADDMUL(t0, a4, b1_19);

    t1 = mul64(a0, b1);
    ADDMUL(t1, a1, b0);
    ADDMUL(t1, a2, b4_19);
    ADDMUL(t1, a3, b3_19);
    ADDMUL(t1, a4, b2_19);

    t2 = mul64(a0, b2);
    ADDMUL(t2, a1, b1);
    ADDMUL(t2, a2, b0);
    ADDMUL(t2, a3, b4_19);
    ADDMUL(t2, a4, b3_19);

    t3 = mul64(a0, b3);
    ADDMUL(t3, a1, b2);
    ADDMUL(t3, a2, b1);
    ADDMUL(t3, a3, b0);
    ADDMUL(t3, a4, b4_19);

    t4 = mul64(a0, b4);
    ADDMUL(t4, a1, b3);
    ADDMUL(t4, a2, b2);
    ADDMUL(t4, a3, b1);
    ADDMUL(t4, a4, b0);

    #undef ADDMUL

    /* Propagate carries at 51-bit boundaries */
    Fe r;
    u64 c;
    #define CARRY(I, J) c = t##I.lo >> 51; t##J.lo += c + (t##I.hi << 13); t##I.lo &= 0x7ffffffffffffULL; t##I.hi = 0
    CARRY(0, 1); CARRY(1, 2); CARRY(2, 3); CARRY(3, 4);
    /* Final carry reduces via ×19 */
    c = t4.lo >> 51; t4.lo &= 0x7ffffffffffffULL;
    t0.lo += c * 19;
    c = t0.lo >> 51; t0.lo &= 0x7ffffffffffffULL;
    t1.lo += c;
    #undef CARRY

    r.v[0] = t0.lo; r.v[1] = t1.lo; r.v[2] = t2.lo;
    r.v[3] = t3.lo; r.v[4] = t4.lo;
    return r;
}

static VISION_INLINE Fe fe_sq(const Fe* a) { return fe_mul(a, a); }

static Fe fe_mul121666(const Fe* a) {
    /* Multiply by 121666 = (A-2)/4 for Montgomery ladder */
    Fe r;
    for (i32 i = 0; i < 5; i++) r.v[i] = a->v[i] * 121666ULL;
    /* Carry */
    for (i32 i = 0; i < 4; i++) { r.v[i+1] += r.v[i] >> 51; r.v[i] &= 0x7ffffffffffffULL; }
    r.v[0] += (r.v[4] >> 51) * 19; r.v[4] &= 0x7ffffffffffffULL;
    return r;
}

/* fe^(p-2) mod p — modular inverse via Fermat's little theorem */
static Fe fe_inv(const Fe* z) {
    /* Addition chain for 2^255-21 */
    Fe z2   = fe_sq(z);
    Fe z4   = fe_sq(&z2);
    Fe z8   = fe_sq(&z4);
    Fe z9   = fe_mul(z, &z8);
    Fe z11  = fe_mul(&z9, &z2);
    Fe z22  = fe_sq(&z11);
    Fe z_5_0 = fe_mul(&z22, &z9);

    Fe t = fe_sq(&z_5_0);
    for (i32 i = 1; i < 5; i++) t = fe_sq(&t);
    Fe z_10_0 = fe_mul(&t, &z_5_0);

    t = fe_sq(&z_10_0);
    for (i32 i = 1; i < 10; i++) t = fe_sq(&t);
    Fe z_20_0 = fe_mul(&t, &z_10_0);

    t = fe_sq(&z_20_0);
    for (i32 i = 1; i < 20; i++) t = fe_sq(&t);
    t = fe_mul(&t, &z_20_0);

    t = fe_sq(&t);
    for (i32 i = 1; i < 10; i++) t = fe_sq(&t);
    Fe z_40_0 = fe_mul(&t, &z_10_0);

    t = fe_sq(&z_40_0);
    for (i32 i = 1; i < 40; i++) t = fe_sq(&t);
    t = fe_mul(&t, &z_40_0);

    t = fe_sq(&t);
    for (i32 i = 1; i < 5; i++) t = fe_sq(&t);
    t = fe_mul(&t, &z_5_0);

    t = fe_sq(&t);
    for (i32 i = 1; i < 25; i++) t = fe_sq(&t);
    Fe z_50_0 = fe_mul(&t, &z_40_0);

    t = fe_sq(&z_50_0);
    for (i32 i = 1; i < 50; i++) t = fe_sq(&t);
    t = fe_mul(&t, &z_50_0);

    t = fe_sq(&t);
    for (i32 i = 1; i < 25; i++) t = fe_sq(&t);
    t = fe_mul(&t, &z_40_0);

    t = fe_sq(&t);
    for (i32 i = 1; i < 5; i++) t = fe_sq(&t);
    return fe_mul(&t, &z_5_0);
}

/* ── Constant-time conditional swap ─────────────────────────────────── */
static VISION_INLINE void fe_cswap(Fe* a, Fe* b, u64 swap) {
    /* swap = 0 or 1; mask = 0 or all-ones */
    u64 mask = (u64)(-(i64)swap);
    for (i32 i = 0; i < 5; i++) {
        u64 t = mask & (a->v[i] ^ b->v[i]);
        a->v[i] ^= t;
        b->v[i] ^= t;
    }
}

/* ── Montgomery ladder scalar multiplication ────────────────────────── */
static void x25519_ladder(const u8 scalar[32], const Fe* u, u8 out[32]) {
    /* Clamp scalar per RFC 7748 */
    u8 e[32];
    vision_memcpy(e, scalar, 32);
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;

    Fe x1 = *u;
    Fe x2 = ONE;
    Fe z2 = ZERO;
    Fe x3 = *u;
    Fe z3 = ONE;

    u64 swap = 0;
    for (i32 pos = 254; pos >= 0; pos--) {
        u64 bit = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(&x2, &x3, swap);
        fe_cswap(&z2, &z3, swap);
        swap = bit;

        Fe A  = fe_add(&x2, &z2);
        Fe AA = fe_sq(&A);
        Fe B  = fe_sub(&x2, &z2);
        Fe BB = fe_sq(&B);
        Fe E  = fe_sub(&AA, &BB);
        Fe C  = fe_add(&x3, &z3);
        Fe D  = fe_sub(&x3, &z3);
        Fe DA = fe_mul(&D, &A);
        Fe CB = fe_mul(&C, &B);
        Fe t1 = fe_add(&DA, &CB); x3 = fe_sq(&t1);
        Fe t2 = fe_sub(&DA, &CB); Fe t3 = fe_sq(&t2);
        z3 = fe_mul(&t3, &x1);
        x2 = fe_mul(&AA, &BB);
        Fe t4 = fe_mul121666(&E);
        Fe t5 = fe_add(&AA, &t4);
        z2 = fe_mul(&E, &t5);
    }

    fe_cswap(&x2, &x3, swap);
    fe_cswap(&z2, &z3, swap);

    Fe inv = fe_inv(&z2);
    Fe res = fe_mul(&x2, &inv);
    fe_store(&res, out);
}

/* ── Public API ─────────────────────────────────────────────────────── */

/* Curve25519 base point u=9 */
static const u8 BASE_POINT[32] = { 9, 0 };

void vision_x25519_pubkey(const u8 priv[32], u8 pub[32]) {
    Fe u = fe_load(BASE_POINT);
    x25519_ladder(priv, &u, pub);
}

i32 vision_x25519(const u8 priv[32], const u8 peer[32], u8 shared[32]) {
    Fe u = fe_load(peer);
    x25519_ladder(priv, &u, shared);

    /* Check for low-order point — output must not be all-zero */
    u8 diff = 0;
    for (i32 i = 0; i < 32; i++) diff |= shared[i];
    return (diff == 0) ? -1 : 0;
}
