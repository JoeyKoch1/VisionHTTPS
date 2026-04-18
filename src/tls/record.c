#include "record.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/chacha20.h"
#include "vision/platform.h"

static void build_nonce(const u8 iv[12], u64 seq, u8 nonce[12]) {
    vision_memcpy(nonce, iv, 12);
    for (i32 i = 0; i < 8; i++)
        nonce[4 + i] ^= (u8)(seq >> (56 - i * 8));
}

i32 vision_tls_record_init(TlsRecordCtx* ctx, TlsHandshakeCtx* hs) {
    vision_memset(ctx, 0, sizeof(*ctx));
    ctx->hs       = hs;
    ctx->send_seq = 0;
    ctx->recv_seq = 0;

    if (vision_aesgcm_init(&ctx->aead_send, hs->server_app_key, 16) != 0) return -1;
    if (vision_aesgcm_init(&ctx->aead_recv, hs->client_app_key, 16) != 0) return -1;
    return 0;
}

isize vision_tls_record_send(TlsRecordCtx* ctx,
                              const u8* plaintext, usize pt_len,
                              u8*       out,        usize out_cap) {

    if (pt_len > 16384) return -1;
    usize inner_len = pt_len + 1;
    usize wire_len  = 5 + inner_len + 16;
    if (out_cap < wire_len) return -1;

    u8 inner[16385];
    vision_memcpy(inner, plaintext, pt_len);
    inner[pt_len] = 0x17;

    u8 nonce[12];
    build_nonce(ctx->hs->server_app_iv, ctx->send_seq, nonce);

    u8 aad[5];
    u16 outer_len = (u16)(inner_len + 16);
    aad[0] = 0x17; aad[1] = 0x03; aad[2] = 0x03;
    aad[3] = (u8)(outer_len >> 8); aad[4] = (u8)outer_len;

    vision_memcpy(out, aad, 5);

    u8 tag[16];
    if (vision_aesgcm_seal(&ctx->aead_send, nonce,
                            aad, 5,
                            inner, inner_len,
                            out + 5, tag) != 0) return -1;
    vision_memcpy(out + 5 + inner_len, tag, 16);

    ctx->send_seq++;
    return (isize)wire_len;
}

isize vision_tls_record_recv(TlsRecordCtx* ctx,
                              const u8* in,  usize in_len,
                              u8*       out, usize out_cap) {
    if (in_len < 5) return 0;

    u8  rec_type = in[0];
    u16 rec_len  = (u16)(((u16)in[3] << 8) | in[4]);

    if (rec_type != 0x17) return -1;
    if (rec_len  < 17)    return -1;
    if (in_len < (usize)(5 + rec_len)) return 0;

    usize ct_len = rec_len - 16;
    if (out_cap < ct_len) return -1;

    u8 nonce[12];
    build_nonce(ctx->hs->client_app_iv, ctx->recv_seq, nonce);

    const u8* tag = in + 5 + ct_len;

    if (vision_aesgcm_open(&ctx->aead_recv, nonce,
                            in, 5,
                            in + 5, ct_len,
                            tag, out) != 0) return -1;

    ctx->recv_seq++;

    if (ct_len < 1) return -1;
    return (isize)ct_len;
}
