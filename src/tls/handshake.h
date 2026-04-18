#ifndef VISION_TLS_HANDSHAKE_H
#define VISION_TLS_HANDSHAKE_H

#include "vision/platform.h"

#define TLS_CT_CHANGE_CIPHER_SPEC  20
#define TLS_CT_ALERT               21
#define TLS_CT_HANDSHAKE           22
#define TLS_CT_APPLICATION_DATA    23

#define TLS_HS_CLIENT_HELLO        1
#define TLS_HS_SERVER_HELLO        2
#define TLS_HS_ENCRYPTED_EXTS      8
#define TLS_HS_CERTIFICATE         11
#define TLS_HS_CERT_VERIFY         15
#define TLS_HS_FINISHED            20

#define TLS_EXT_SERVER_NAME        0x0000
#define TLS_EXT_SUPPORTED_GROUPS   0x000a
#define TLS_EXT_SIG_ALGS           0x000d
#define TLS_EXT_SUPPORTED_VERSIONS 0x002b
#define TLS_EXT_KEY_SHARE          0x0033

#define TLS_GROUP_X25519           0x001d

#define TLS_AES_128_GCM_SHA256     0x1301
#define TLS_AES_256_GCM_SHA384     0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303

#define TLS_ALERT_CLOSE_NOTIFY            0
#define TLS_ALERT_UNEXPECTED_MESSAGE      10
#define TLS_ALERT_BAD_RECORD_MAC          20
#define TLS_ALERT_HANDSHAKE_FAILURE       40
#define TLS_ALERT_DECODE_ERROR            50
#define TLS_ALERT_ILLEGAL_PARAMETER       47
#define TLS_ALERT_PROTOCOL_VERSION        70
#define TLS_ALERT_INTERNAL_ERROR          80

#define TLS_HASH_LEN     32
#define TLS_KEY_LEN      16
#define TLS_IV_LEN       12

typedef enum {
    TLS_HS_STATE_INIT          = 0,
    TLS_HS_STATE_WAIT_CH       = 1,
    TLS_HS_STATE_WAIT_FINISHED = 2,
    TLS_HS_STATE_DONE          = 3,
    TLS_HS_STATE_ERROR         = 4,
} TlsHsState;

typedef struct {
    TlsHsState state;

    u8 server_priv[32];
    u8 server_pub[32];
    u8 client_pub[32];

    u8 shared_secret[32];
    u8 early_secret[TLS_HASH_LEN];
    u8 hs_secret[TLS_HASH_LEN];
    u8 master_secret[TLS_HASH_LEN];

    u8 server_hs_key[TLS_KEY_LEN];
    u8 server_hs_iv[TLS_IV_LEN];
    u8 client_hs_key[TLS_KEY_LEN];
    u8 client_hs_iv[TLS_IV_LEN];
    u8 server_app_key[TLS_KEY_LEN];
    u8 server_app_iv[TLS_IV_LEN];
    u8 client_app_key[TLS_KEY_LEN];
    u8 client_app_iv[TLS_IV_LEN];

    u8  transcript[4096];
    usize transcript_len;

    u16 cipher_suite;

    u64 server_seq;
    u64 client_seq;

    const u8* cert_der;
    usize     cert_der_len;
    const u8* key_der;
    usize     key_der_len;
} TlsHandshakeCtx;

#ifdef __cplusplus
extern "C" {
#endif

void vision_tls_hs_init(TlsHandshakeCtx* ctx,
                         const u8* cert_der, usize cert_len,
                         const u8* key_der,  usize key_len);

i32 vision_tls_hs_consume(TlsHandshakeCtx* ctx,
                           const u8* in,  usize in_len,
                           u8*       out, usize* out_len);

bool8 vision_tls_hs_complete(const TlsHandshakeCtx* ctx);

#ifdef __cplusplus
}
#endif

#endif
