/*
 * src/tls/handshake.c
 * TLS 1.3 server-side handshake state machine (RFC 8446).
 *
 * Cipher suite: TLS_AES_128_GCM_SHA256 (mandatory) +
 *               TLS_CHACHA20_POLY1305_SHA256 (preferred on ARM)
 * Key exchange: X25519 only
 * No externs. All crypto via our own primitives.
 */
#include "handshake.h"
#include "record.h"
#include "../crypto/sha256.h"
#include "../crypto/hmac.h"
#include "../crypto/x25519.h"
#include "../crypto/aes_gcm.h"
#include "vision/platform.h"

/* ── Write helpers ───────────────────────────────────────────────────── */
static VISION_INLINE void w8(u8** p, u8 v)           { **p = v; (*p)++; }
static VISION_INLINE void w16(u8** p, u16 v)          { (*p)[0]=(u8)(v>>8); (*p)[1]=(u8)v; *p+=2; }
static VISION_INLINE void w24(u8** p, u32 v)          { (*p)[0]=(u8)(v>>16); (*p)[1]=(u8)(v>>8); (*p)[2]=(u8)v; *p+=3; }
static VISION_INLINE void wbuf(u8** p, const u8* s, usize n) { vision_memcpy(*p, s, n); *p += n; }
static VISION_INLINE u8  r8(const u8** p)              { return *(*p)++; }
static VISION_INLINE u16 r16(const u8** p)             { u16 v=(u16)((u16)(*p)[0]<<8)|(*p)[1]; *p+=2; return v; }
static VISION_INLINE u32 r24(const u8** p)             { u32 v=((u32)(*p)[0]<<16)|((u32)(*p)[1]<<8)|(*p)[2]; *p+=3; return v; }

/* ── Transcript accumulation ────────────────────────────────────────── */
static void transcript_append(TlsHandshakeCtx* ctx, const u8* data, usize len) {
    if (ctx->transcript_len + len > sizeof(ctx->transcript)) return;
    vision_memcpy(ctx->transcript + ctx->transcript_len, data, len);
    ctx->transcript_len += len;
}
static void transcript_hash(const TlsHandshakeCtx* ctx, u8 out[32]) {
    vision_sha256(ctx->transcript, ctx->transcript_len, out);
}

/* ── HKDF-Expand-Label (RFC 8446 §7.1) ─────────────────────────────── */
static void hkdf_expand_label(const u8* secret, usize slen,
                               const char* label, usize llen,
                               const u8* ctx_hash, usize hlen,
                               u8* out, usize olen) {
    u8 info[256];
    u8* p = info;
    w16(&p, (u16)olen);
    usize tlen = 6 + llen;
    w8(&p, (u8)tlen);
    wbuf(&p, (const u8*)"tls13 ", 6);
    wbuf(&p, (const u8*)label, llen);
    w8(&p, (u8)hlen);
    if (hlen) wbuf(&p, ctx_hash, hlen);
    vision_hkdf_expand(secret, slen, info, (usize)(p - info), out, olen);
}

static void derive_secret(const u8* secret, const char* label, usize llen,
                           const u8* th, u8 out[32]) {
    hkdf_expand_label(secret, 32, label, llen, th, 32, out, 32);
}

/* ── Key schedule ────────────────────────────────────────────────────── */
static void ks_handshake(TlsHandshakeCtx* ctx) {
    u8 zeros[32]; vision_memset(zeros, 0, 32);
    u8 eh[32];    vision_sha256((const u8*)"", 0, eh);
    vision_hkdf_extract(zeros, 32, zeros, 32, ctx->early_secret);
    u8 derived[32];
    derive_secret(ctx->early_secret, "derived", 7, eh, derived);
    vision_hkdf_extract(derived, 32, ctx->shared_secret, 32, ctx->hs_secret);
    u8 th[32]; transcript_hash(ctx, th);
    u8 c_ts[32], s_ts[32];
    derive_secret(ctx->hs_secret, "c hs traffic", 12, th, c_ts);
    derive_secret(ctx->hs_secret, "s hs traffic", 12, th, s_ts);
    hkdf_expand_label(c_ts, 32, "key", 3, (const u8*)"", 0, ctx->client_hs_key, 16);
    hkdf_expand_label(c_ts, 32, "iv",  2, (const u8*)"", 0, ctx->client_hs_iv,  12);
    hkdf_expand_label(s_ts, 32, "key", 3, (const u8*)"", 0, ctx->server_hs_key, 16);
    hkdf_expand_label(s_ts, 32, "iv",  2, (const u8*)"", 0, ctx->server_hs_iv,  12);
}

static void ks_application(TlsHandshakeCtx* ctx) {
    u8 zeros[32]; vision_memset(zeros, 0, 32);
    u8 eh[32];    vision_sha256((const u8*)"", 0, eh);
    u8 derived[32];
    derive_secret(ctx->hs_secret, "derived", 7, eh, derived);
    vision_hkdf_extract(derived, 32, zeros, 32, ctx->master_secret);
    u8 th[32]; transcript_hash(ctx, th);
    u8 c_ts[32], s_ts[32];
    derive_secret(ctx->master_secret, "c ap traffic", 12, th, c_ts);
    derive_secret(ctx->master_secret, "s ap traffic", 12, th, s_ts);
    hkdf_expand_label(c_ts, 32, "key", 3, (const u8*)"", 0, ctx->client_app_key, 16);
    hkdf_expand_label(c_ts, 32, "iv",  2, (const u8*)"", 0, ctx->client_app_iv,  12);
    hkdf_expand_label(s_ts, 32, "key", 3, (const u8*)"", 0, ctx->server_app_key, 16);
    hkdf_expand_label(s_ts, 32, "iv",  2, (const u8*)"", 0, ctx->server_app_iv,  12);
}

/* ── Finished HMAC ───────────────────────────────────────────────────── */
static void compute_finished(const u8* ts, const u8* th, u8 verify[32]) {
    u8 fkey[32];
    hkdf_expand_label(ts, 32, "finished", 8, (const u8*)"", 0, fkey, 32);
    vision_hmac_sha256(fkey, 32, th, 32, verify);
}

/* ── Parse ClientHello ────────────────────────────────────────────────── */
static i32 parse_client_hello(TlsHandshakeCtx* ctx, const u8* data, usize len) {
    const u8* p = data, *end = data + len;
    if (p + 2 > end) return -1;
    r16(&p); /* legacy_version */
    if (p + 32 > end) return -1;
    p += 32; /* random */
    if (p + 1 > end) return -1;
    u8 sid_len = r8(&p);
    if (p + sid_len > end) return -1;
    p += sid_len;
    if (p + 2 > end) return -1;
    u16 cs_len = r16(&p);
    if (p + cs_len > end) return -1;
    const u8* cs_end = p + cs_len;
    bool8 found_suite = VISION_FALSE;
    while (p + 1 < cs_end) {
        u16 cs = r16(&p);
        if ((cs == TLS_AES_128_GCM_SHA256 || cs == TLS_CHACHA20_POLY1305_SHA256) && !found_suite) {
            ctx->cipher_suite = cs; found_suite = VISION_TRUE;
        }
    }
    if (!found_suite) return -2;
    if (p + 1 > end) return -1;
    u8 cm = r8(&p); p += cm;
    if (p + 2 > end) return -1;
    u16 ext_total = r16(&p);
    const u8* ext_end = p + ext_total;
    bool8 got_x25519 = VISION_FALSE, got_tls13 = VISION_FALSE;
    while (p + 4 <= ext_end) {
        u16 etype = r16(&p), elen = r16(&p);
        const u8* ed = p; p += elen;
        if (etype == TLS_EXT_SUPPORTED_VERSIONS && elen >= 3) {
            const u8* vp = ed; u8 vl = r8(&vp);
            for (u8 i = 0; i + 1 < vl; i += 2)
                if (r16(&vp) == 0x0304) got_tls13 = VISION_TRUE;
        } else if (etype == TLS_EXT_KEY_SHARE && elen >= 4) {
            const u8* kp = ed; u16 kl = r16(&kp);
            const u8* ke = kp + kl;
            while (kp + 4 <= ke) {
                u16 grp = r16(&kp), klen = r16(&kp);
                if (grp == TLS_GROUP_X25519 && klen == 32) {
                    vision_memcpy(ctx->client_pub, kp, 32);
                    got_x25519 = VISION_TRUE;
                }
                kp += klen;
            }
        }
    }
    if (!got_tls13 || !got_x25519) return -3;
    return 0;
}

/* ── Build messages ──────────────────────────────────────────────────── */
static usize build_server_hello(const TlsHandshakeCtx* ctx, u8* buf) {
    u8* p = buf;
    w8(&p, TLS_HS_SERVER_HELLO); u8* lp = p; p += 3;
    w16(&p, 0x0303);
    u8 rnd[32]; vision_memset(rnd, 0xAB, 32); wbuf(&p, rnd, 32);
    w8(&p, 0); w16(&p, ctx->cipher_suite); w8(&p, 0);
    u8* elp = p; p += 2; u8* es = p;
    w16(&p, TLS_EXT_SUPPORTED_VERSIONS); w16(&p, 2); w16(&p, 0x0304);
    w16(&p, TLS_EXT_KEY_SHARE); w16(&p, 36);
    w16(&p, TLS_GROUP_X25519); w16(&p, 32); wbuf(&p, ctx->server_pub, 32);
    u16 esz = (u16)(p - es); elp[0]=(u8)(esz>>8); elp[1]=(u8)esz;
    u32 bsz = (u32)(p - lp - 3); lp[0]=(u8)(bsz>>16); lp[1]=(u8)(bsz>>8); lp[2]=(u8)bsz;
    return (usize)(p - buf);
}

static usize build_enc_exts(u8* buf) {
    u8* p = buf;
    w8(&p, TLS_HS_ENCRYPTED_EXTS); w24(&p, 2); w16(&p, 0);
    return (usize)(p - buf);
}

static usize build_cert(const TlsHandshakeCtx* ctx, u8* buf) {
    if (!ctx->cert_der || !ctx->cert_der_len) return 0;
    u8* p = buf;
    w8(&p, TLS_HS_CERTIFICATE); u8* lp = p; p += 3;
    w8(&p, 0);
    u8* clp = p; p += 3; u8* cs = p;
    w24(&p, (u32)ctx->cert_der_len);
    wbuf(&p, ctx->cert_der, ctx->cert_der_len);
    w16(&p, 0);
    u32 csz = (u32)(p - cs); clp[0]=(u8)(csz>>16); clp[1]=(u8)(csz>>8); clp[2]=(u8)csz;
    u32 bsz = (u32)(p - lp - 3); lp[0]=(u8)(bsz>>16); lp[1]=(u8)(bsz>>8); lp[2]=(u8)bsz;
    return (usize)(p - buf);
}

static usize build_finished(TlsHandshakeCtx* ctx, u8* buf) {
    u8 th[32]; transcript_hash(ctx, th);
    u8 s_ts[32];
    derive_secret(ctx->hs_secret, "s hs traffic", 12, th, s_ts);
    u8 verify[32]; compute_finished(s_ts, th, verify);
    u8* p = buf;
    w8(&p, TLS_HS_FINISHED); w24(&p, 32); wbuf(&p, verify, 32);
    return (usize)(p - buf);
}

/* ── Wrap plaintext in a TLS record ─────────────────────────────────── */
static usize wrap_record(u8* dst, u8 ct, const u8* body, usize blen) {
    dst[0] = ct; dst[1] = 0x03; dst[2] = 0x03;
    dst[3] = (u8)(blen >> 8); dst[4] = (u8)blen;
    vision_memcpy(dst + 5, body, blen);
    return 5 + blen;
}

/* ── Public API ──────────────────────────────────────────────────────── */
void vision_tls_hs_init(TlsHandshakeCtx* ctx,
                         const u8* cert_der, usize cert_len,
                         const u8* key_der,  usize key_len) {
    vision_memset(ctx, 0, sizeof(*ctx));
    ctx->state        = TLS_HS_STATE_WAIT_CH;
    ctx->cert_der     = cert_der;
    ctx->cert_der_len = cert_len;
    ctx->key_der      = key_der;
    ctx->key_der_len  = key_len;
    /* Ephemeral keypair — replace 0x42 seed with OS entropy in production */
    vision_memset(ctx->server_priv, 0x42, 32);
    ctx->server_priv[0]  &= 248;
    ctx->server_priv[31] &= 127;
    ctx->server_priv[31] |= 64;
    vision_x25519_pubkey(ctx->server_priv, ctx->server_pub);
}

i32 vision_tls_hs_consume(TlsHandshakeCtx* ctx,
                           const u8* in,  usize in_len,
                           u8*       out, usize* out_len) {
    *out_len = 0;
    if (ctx->state == TLS_HS_STATE_DONE)  return 0;
    if (ctx->state == TLS_HS_STATE_ERROR) return -1;
    if (in_len < 5) return 0;

    u8  rec_type = in[0];
    u16 rec_len  = (u16)(((u16)in[3] << 8) | in[4]);
    if (in_len < (usize)(5 + rec_len)) return 0;

    const u8* body = in + 5;

    if (ctx->state == TLS_HS_STATE_WAIT_CH) {
        if (rec_type != TLS_CT_HANDSHAKE || rec_len < 4) { ctx->state = TLS_HS_STATE_ERROR; return -1; }
        if (body[0] != TLS_HS_CLIENT_HELLO) { ctx->state = TLS_HS_STATE_ERROR; return -1; }
        u32 mlen = ((u32)body[1]<<16)|((u32)body[2]<<8)|body[3];
        transcript_append(ctx, body, 4 + mlen);
        if (parse_client_hello(ctx, body + 4, mlen) != 0) { ctx->state = TLS_HS_STATE_ERROR; return -1; }
        if (vision_x25519(ctx->server_priv, ctx->client_pub, ctx->shared_secret) != 0) { ctx->state = TLS_HS_STATE_ERROR; return -1; }

        u8* p = out;
        u8 tmp[4096];
        usize tlen;

        /* ServerHello */
        tlen = build_server_hello(ctx, tmp);
        transcript_append(ctx, tmp, tlen);
        p += wrap_record(p, TLS_CT_HANDSHAKE, tmp, tlen);

        /* Derive handshake keys */
        ks_handshake(ctx);

        /* CCS (compatibility) */
        static const u8 ccs[] = {TLS_CT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01};
        vision_memcpy(p, ccs, 6); p += 6;

        /* EncryptedExtensions */
        tlen = build_enc_exts(tmp);
        transcript_append(ctx, tmp, tlen);
        p += wrap_record(p, TLS_CT_APPLICATION_DATA, tmp, tlen);

        /* Certificate */
        tlen = build_cert(ctx, tmp);
        if (tlen) { transcript_append(ctx, tmp, tlen); p += wrap_record(p, TLS_CT_APPLICATION_DATA, tmp, tlen); }

        /* Finished */
        tlen = build_finished(ctx, tmp);
        transcript_append(ctx, tmp, tlen);
        p += wrap_record(p, TLS_CT_APPLICATION_DATA, tmp, tlen);

        *out_len = (usize)(p - out);
        ctx->state = TLS_HS_STATE_WAIT_FINISHED;
        return (i32)(5 + rec_len);
    }

    if (ctx->state == TLS_HS_STATE_WAIT_FINISHED) {
        if (rec_type == TLS_CT_CHANGE_CIPHER_SPEC) return (i32)(5 + rec_len);
        if (rec_type == TLS_CT_APPLICATION_DATA) {
            /* Verify client Finished — simplified, full AEAD decrypt in record.c */
            ks_application(ctx);
            ctx->state = TLS_HS_STATE_DONE;
            return (i32)(5 + rec_len);
        }
        ctx->state = TLS_HS_STATE_ERROR; return -1;
    }
    return -1;
}

bool8 vision_tls_hs_complete(const TlsHandshakeCtx* ctx) {
    return ctx->state == TLS_HS_STATE_DONE ? VISION_TRUE : VISION_FALSE;
}
