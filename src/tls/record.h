#ifndef VISION_TLS_RECORD_H
#define VISION_TLS_RECORD_H

#include "vision/platform.h"
#include "handshake.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/chacha20.h"

typedef struct {
    TlsHandshakeCtx* hs;
    u64              send_seq;
    u64              recv_seq;
    VisionAesGcmCtx  aead_send;
    VisionAesGcmCtx  aead_recv;
} TlsRecordCtx;

#ifdef __cplusplus
extern "C" {
#endif

i32   vision_tls_record_init(TlsRecordCtx* ctx, TlsHandshakeCtx* hs);

isize vision_tls_record_send(TlsRecordCtx* ctx,
                              const u8* plaintext, usize pt_len,
                              u8*       out,        usize out_cap);

isize vision_tls_record_recv(TlsRecordCtx* ctx,
                              const u8* in,  usize in_len,
                              u8*       out, usize out_cap);

#ifdef __cplusplus
}
#endif

#endif
