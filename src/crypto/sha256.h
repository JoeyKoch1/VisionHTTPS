#ifndef VISION_CRYPTO_SHA256_H
#define VISION_CRYPTO_SHA256_H

#include "vision/platform.h"

#define VISION_SHA256_DIGEST_SIZE  32
#define VISION_SHA256_BLOCK_SIZE   64

typedef struct {
    u32  state[8];
    u64  bitcount;
    u8   buf[VISION_SHA256_BLOCK_SIZE];
    u32  buf_len;
} VisionSha256Ctx;

#ifdef __cplusplus
extern "C" {
#endif

void vision_sha256_init(VisionSha256Ctx* ctx);
void vision_sha256_update(VisionSha256Ctx* ctx, const u8* data, usize len);
void vision_sha256_final(VisionSha256Ctx* ctx, u8 out[VISION_SHA256_DIGEST_SIZE]);

void vision_sha256(const u8* data, usize len, u8 out[VISION_SHA256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
