#ifndef VISION_CRYPTO_HMAC_H
#define VISION_CRYPTO_HMAC_H

#include "vision/platform.h"
#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

void vision_hmac_sha256(const u8*  key,  usize key_len,
                         const u8*  data, usize data_len,
                         u8         out[VISION_SHA256_DIGEST_SIZE]);

void vision_hkdf_extract(const u8*  salt, usize salt_len,
                           const u8*  ikm,  usize ikm_len,
                           u8         prk[VISION_SHA256_DIGEST_SIZE]);

i32  vision_hkdf_expand(const u8*  prk,  usize prk_len,
                          const u8*  info, usize info_len,
                          u8*        okm,  usize okm_len);

#ifdef __cplusplus
}
#endif

#endif
