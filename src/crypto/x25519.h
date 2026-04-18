#ifndef VISION_CRYPTO_X25519_H
#define VISION_CRYPTO_X25519_H

#include "vision/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

void vision_x25519_pubkey(const u8 private_key[32], u8 public_key[32]);

i32  vision_x25519(const u8 private_key[32],
                   const u8 peer_public[32],
                   u8       shared_secret[32]);

#ifdef __cplusplus
}
#endif

#endif
