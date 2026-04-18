#ifndef VISION_TLS_RECORD_H
#define VISION_TLS_RECORD_H

#include "vision/platform.h"
#include "handshake.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/chacha20.h"

/*
 * TLS 1.3 record layer.
 * Handles AEAD encrypt/decrypt of application data records
 * using keys established by the handshake.
 */

typedef struct {
    TlsHandshakeCtx* hs;          /* back-pointer to key material      */
    u64              send_seq;     /* outbound sequence counter          */
    u64              recv_seq;     /* inbound  sequence counter          */
    VisionAesGcmCtx  aead_send;   /* initialized from app traffic key   */
    VisionAesGcmCtx  aead_recv;
} TlsRecordCtx;

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize record context after handshake completes */
i32   vision_tls_record_init(TlsRecordCtx* ctx, TlsHandshakeCtx* hs);

/*
 * Encrypt plaintext → TLS ApplicationData record.
 * out must have capacity >= pt_len + 22  (5 header + 16 tag + 1 content type)
 * Returns total bytes written to out, or -1 on error.
 */
isize vision_tls_record_send(TlsRecordCtx* ctx,
                              const u8* plaintext, usize pt_len,
                              u8*       out,        usize out_cap);

/*
 * Decrypt one TLS ApplicationData record.
 * Returns plaintext length, 0 if more data needed, -1 on auth failure.
 */
isize vision_tls_record_recv(TlsRecordCtx* ctx,
                              const u8* in,  usize in_len,
                              u8*       out, usize out_cap);

#ifdef __cplusplus
}
#endif

#endif /* VISION_TLS_RECORD_H */
