#ifndef VISION_CRYPTO_CHACHA20_H
#define VISION_CRYPTO_CHACHA20_H

#include "vision/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

i32 vision_chacha20poly1305_seal(
        const u8*  key,
        const u8*  nonce,
        const u8*  aad,  usize  aad_len,
        const u8*  pt,   usize  pt_len,
        u8*        ct,
        u8         tag[16]);

i32 vision_chacha20poly1305_open(
        const u8*  key,
        const u8*  nonce,
        const u8*  aad,  usize  aad_len,
        const u8*  ct,   usize  ct_len,
        const u8   tag[16],
        u8*        pt); 

#ifdef __cplusplus
}
#endif

#endif
