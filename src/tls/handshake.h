#ifndef VISION_TLS_HANDSHAKE_H
#define VISION_TLS_HANDSHAKE_H

#include "vision/platform.h"

/* ── TLS 1.3 record content types ──────────────────────────────────── */
#define TLS_CT_CHANGE_CIPHER_SPEC  20
#define TLS_CT_ALERT               21
#define TLS_CT_HANDSHAKE           22
#define TLS_CT_APPLICATION_DATA    23

/* ── TLS 1.3 handshake message types ───────────────────────────────── */
#define TLS_HS_CLIENT_HELLO        1
#define TLS_HS_SERVER_HELLO        2
#define TLS_HS_ENCRYPTED_EXTS      8
#define TLS_HS_CERTIFICATE         11
#define TLS_HS_CERT_VERIFY         15
#define TLS_HS_FINISHED            20

/* ── TLS 1.3 extensions ─────────────────────────────────────────────── */
#define TLS_EXT_SERVER_NAME        0x0000
#define TLS_EXT_SUPPORTED_GROUPS   0x000a
#define TLS_EXT_SIG_ALGS           0x000d
#define TLS_EXT_SUPPORTED_VERSIONS 0x002b
#define TLS_EXT_KEY_SHARE          0x0033

/* ── Named groups ────────────────────────────────────────────────────── */
#define TLS_GROUP_X25519           0x001d

/* ── Cipher suites ───────────────────────────────────────────────────── */
#define TLS_AES_128_GCM_SHA256     0x1301
#define TLS_AES_256_GCM_SHA384     0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303

/* ── Alert descriptions ──────────────────────────────────────────────── */
#define TLS_ALERT_CLOSE_NOTIFY            0
#define TLS_ALERT_UNEXPECTED_MESSAGE      10
#define TLS_ALERT_BAD_RECORD_MAC          20
#define TLS_ALERT_HANDSHAKE_FAILURE       40
#define TLS_ALERT_DECODE_ERROR            50
#define TLS_ALERT_ILLEGAL_PARAMETER       47
#define TLS_ALERT_PROTOCOL_VERSION        70
#define TLS_ALERT_INTERNAL_ERROR          80

/* ── Key schedule buffers ────────────────────────────────────────────── */
#define TLS_HASH_LEN     32   /* SHA-256 output */
#define TLS_KEY_LEN      16   /* AES-128 key    */
#define TLS_IV_LEN       12   /* GCM/ChaCha IV  */

typedef enum {
    TLS_HS_STATE_INIT          = 0,
    TLS_HS_STATE_WAIT_CH       = 1,   /* server: waiting for ClientHello   */
    TLS_HS_STATE_WAIT_FINISHED = 2,   /* server: waiting for client Finished */
    TLS_HS_STATE_DONE          = 3,
    TLS_HS_STATE_ERROR         = 4,
} TlsHsState;

typedef struct {
    TlsHsState state;

    /* Ephemeral X25519 keypair (server side) */
    u8 server_priv[32];
    u8 server_pub[32];
    u8 client_pub[32];     /* from ClientHello key_share */

    /* Shared secret → key schedule */
    u8 shared_secret[32];
    u8 early_secret[TLS_HASH_LEN];
    u8 hs_secret[TLS_HASH_LEN];
    u8 master_secret[TLS_HASH_LEN];

    /* Traffic keys (server write = client read and vice versa) */
    u8 server_hs_key[TLS_KEY_LEN];
    u8 server_hs_iv[TLS_IV_LEN];
    u8 client_hs_key[TLS_KEY_LEN];
    u8 client_hs_iv[TLS_IV_LEN];
    u8 server_app_key[TLS_KEY_LEN];
    u8 server_app_iv[TLS_IV_LEN];
    u8 client_app_key[TLS_KEY_LEN];
    u8 client_app_iv[TLS_IV_LEN];

    /* Transcript hash accumulator */
    u8  transcript[4096];   /* raw handshake messages for hash */
    usize transcript_len;

    /* Negotiated cipher suite */
    u16 cipher_suite;

    /* Sequence counters */
    u64 server_seq;
    u64 client_seq;

    /* Certificate + private key (DER, set by config loader) */
    const u8* cert_der;
    usize     cert_der_len;
    const u8* key_der;      /* PKCS#8 or raw 32-byte X25519 priv for Ed25519 */
    usize     key_der_len;
} TlsHandshakeCtx;

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize context, generate ephemeral keypair */
void vision_tls_hs_init(TlsHandshakeCtx* ctx,
                         const u8* cert_der, usize cert_len,
                         const u8* key_der,  usize key_len);

/*
 * Feed raw bytes from the network into the handshake state machine.
 * Returns:
 *   > 0  bytes consumed and output written to out_buf / *out_len
 *     0  need more data
 *    -1  fatal error — send alert then close
 */
i32 vision_tls_hs_consume(TlsHandshakeCtx* ctx,
                           const u8* in,  usize in_len,
                           u8*       out, usize* out_len);

/* True once handshake is complete */
bool8 vision_tls_hs_complete(const TlsHandshakeCtx* ctx);

#ifdef __cplusplus
}
#endif

#endif /* VISION_TLS_HANDSHAKE_H */
