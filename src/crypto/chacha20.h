#ifndef VISION_CRYPTO_CHACHA20_H
#define VISION_CRYPTO_CHACHA20_H

#include "vision/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ChaCha20-Poly1305 AEAD (RFC 8439).
 * 32-byte key, 12-byte nonce, 16-byte authentication tag.
 */

i32 vision_chacha20poly1305_seal(
        const u8*  key,         /* 32 bytes */
        const u8*  nonce,       /* 12 bytes */
        const u8*  aad,  usize  aad_len,
        const u8*  pt,   usize  pt_len,
        u8*        ct,          /* pt_len bytes out */
        u8         tag[16]);

i32 vision_chacha20poly1305_open(
        const u8*  key,
        const u8*  nonce,
        const u8*  aad,  usize  aad_len,
        const u8*  ct,   usize  ct_len,
        const u8   tag[16],
        u8*        pt);         /* ct_len bytes out */

#ifdef __cplusplus
}
#endif

#endif /* VISION_CRYPTO_CHACHA20_H */
