#ifndef VISION_CRYPTO_AES_GCM_H
#define VISION_CRYPTO_AES_GCM_H

#include "vision/platform.h"

/*
 * AES-128-GCM and AES-256-GCM AEAD context.
 * key_len == 16 → AES-128, key_len == 32 → AES-256.
 *
 * round_keys layout:
 *   AES-128: 11 × 16 = 176 bytes
 *   AES-256: 15 × 16 = 240 bytes
 * We allocate for the larger case.
 */
typedef struct {
    u8   key[32];
    u32  key_len;          /* 16 or 32 */
    u8   round_keys[240];  /* pre-expanded key schedule */
    u8   h_subkey[16];     /* H = AES_K(0^128) for GHASH */
} VisionAesGcmCtx;

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize context and expand key schedule. Returns 0 on success. */
i32  vision_aesgcm_init(VisionAesGcmCtx* ctx, const u8* key, usize key_len);

/* Internal: encrypt a single 16-byte block (for CTR + H subkey derivation) */
void vision_aesgcm_encrypt_block(const VisionAesGcmCtx* ctx,
                                  const u8 in[16], u8 out[16]);

/*
 * Seal: encrypt plaintext and produce authentication tag.
 * ciphertext must have capacity >= pt_len.
 * Returns 0 on success.
 */
i32  vision_aesgcm_seal(VisionAesGcmCtx* ctx,
                         const u8*  nonce,         /* 12 bytes */
                         const u8*  aad,   usize aad_len,
                         const u8*  plaintext, usize pt_len,
                         u8*        ciphertext,
                         u8         tag_out[16]);

/*
 * Open: verify tag then decrypt ciphertext → plaintext.
 * plaintext must have capacity >= ct_len.
 * Returns 0 on success, -1 on authentication failure.
 */
i32  vision_aesgcm_open(VisionAesGcmCtx* ctx,
                         const u8*  nonce,
                         const u8*  aad,  usize aad_len,
                         const u8*  ciphertext, usize ct_len,
                         const u8   tag_in[16],
                         u8*        plaintext);

#ifdef __cplusplus
}
#endif

#endif /* VISION_CRYPTO_AES_GCM_H */
