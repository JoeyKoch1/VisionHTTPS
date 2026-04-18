#ifndef VISION_CRYPTO_X25519_H
#define VISION_CRYPTO_X25519_H

/*
 * X25519 Elliptic-Curve Diffie-Hellman (RFC 7748).
 * Used in TLS 1.3 key_share extension.
 *
 * All inputs/outputs are 32-byte little-endian field elements.
 */
#include "vision/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generate a public key from a private scalar.
 *   private_key: 32 random bytes (caller provides entropy)
 *   public_key:  32-byte output (X coordinate of scalar * G)
 */
void vision_x25519_pubkey(const u8 private_key[32], u8 public_key[32]);

/*
 * Perform DH: compute shared secret = scalar * peer_public.
 *   Returns 0 on success, -1 if peer_public is a low-order point.
 */
i32  vision_x25519(const u8 private_key[32],
                   const u8 peer_public[32],
                   u8       shared_secret[32]);

#ifdef __cplusplus
}
#endif

#endif /* VISION_CRYPTO_X25519_H */
