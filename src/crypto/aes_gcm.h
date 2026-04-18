#ifndef VISION_CRYPTO_AES_GCM_H
#define VISION_CRYPTO_AES_GCM_H

#include "vision/platform.h"

typedef struct {
    u8   key[32];
    u32  key_len;
    u8   round_keys[240];
    u8   h_subkey[16];
} VisionAesGcmCtx;

#ifdef __cplusplus
extern "C" {
#endif

i32  vision_aesgcm_init(VisionAesGcmCtx* ctx, const u8* key, usize key_len);

void vision_aesgcm_encrypt_block(const VisionAesGcmCtx* ctx,
                                  const u8 in[16], u8 out[16]);

i32  vision_aesgcm_seal(VisionAesGcmCtx* ctx,
                         const u8*  nonce,
                         const u8*  aad,   usize aad_len,
                         const u8*  plaintext, usize pt_len,
                         u8*        ciphertext,
                         u8         tag_out[16]);

i32  vision_aesgcm_open(VisionAesGcmCtx* ctx,
                         const u8*  nonce,
                         const u8*  aad,  usize aad_len,
                         const u8*  ciphertext, usize ct_len,
                         const u8   tag_in[16],
                         u8*        plaintext);

#ifdef __cplusplus
}
#endif

#endif
