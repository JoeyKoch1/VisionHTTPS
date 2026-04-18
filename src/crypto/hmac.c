#include "hmac.h"
#include "sha256.h"
#include "vision/platform.h"

#define BLOCK_SIZE  64
#define DIGEST_SIZE 32

void vision_hmac_sha256(const u8*  key,  usize key_len,
                         const u8*  data, usize data_len,
                         u8         out[VISION_SHA256_DIGEST_SIZE]) {
    u8 k[BLOCK_SIZE];
    vision_memset(k, 0, BLOCK_SIZE);

    if (key_len > BLOCK_SIZE) {
        vision_sha256(key, key_len, k);
    } else {
        vision_memcpy(k, key, key_len);
    }

    u8 ipad[BLOCK_SIZE], opad[BLOCK_SIZE];
    for (i32 i = 0; i < BLOCK_SIZE; i++) {
        ipad[i] = k[i] ^ 0x36u;
        opad[i] = k[i] ^ 0x5cu;
    }

    u8 inner[DIGEST_SIZE];
    VisionSha256Ctx ctx;
    vision_sha256_init(&ctx);
    vision_sha256_update(&ctx, ipad, BLOCK_SIZE);
    vision_sha256_update(&ctx, data, data_len);
    vision_sha256_final(&ctx, inner);

    vision_sha256_init(&ctx);
    vision_sha256_update(&ctx, opad, BLOCK_SIZE);
    vision_sha256_update(&ctx, inner, DIGEST_SIZE);
    vision_sha256_final(&ctx, out);
}

void vision_hkdf_extract(const u8*  salt, usize salt_len,
                           const u8*  ikm,  usize ikm_len,
                           u8         prk[VISION_SHA256_DIGEST_SIZE]) {
    u8 default_salt[DIGEST_SIZE];
    if (!salt || salt_len == 0) {
        vision_memset(default_salt, 0, DIGEST_SIZE);
        salt     = default_salt;
        salt_len = DIGEST_SIZE;
    }
    vision_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

i32 vision_hkdf_expand(const u8*  prk,  usize prk_len,
                         const u8*  info, usize info_len,
                         u8*        okm,  usize okm_len) {
    if (okm_len > 255 * DIGEST_SIZE) return -1;

    u8 t[DIGEST_SIZE];
    vision_memset(t, 0, DIGEST_SIZE);
    usize t_len = 0;

    u8  counter = 1;
    u8* out     = okm;
    usize remaining = okm_len;

    while (remaining > 0) {
        VisionSha256Ctx ctx;
        u8 ipad[BLOCK_SIZE], opad[BLOCK_SIZE];
        u8 k[BLOCK_SIZE];
        vision_memset(k, 0, BLOCK_SIZE);
        if (prk_len <= BLOCK_SIZE) {
            vision_memcpy(k, prk, prk_len);
        } else {
            vision_sha256(prk, prk_len, k);
        }
        for (i32 i = 0; i < BLOCK_SIZE; i++) {
            ipad[i] = k[i] ^ 0x36u;
            opad[i] = k[i] ^ 0x5cu;
        }

        u8 inner[DIGEST_SIZE];
        vision_sha256_init(&ctx);
        vision_sha256_update(&ctx, ipad, BLOCK_SIZE);
        if (t_len) vision_sha256_update(&ctx, t, t_len);
        vision_sha256_update(&ctx, info, info_len);
        vision_sha256_update(&ctx, &counter, 1);
        vision_sha256_final(&ctx, inner);

        vision_sha256_init(&ctx);
        vision_sha256_update(&ctx, opad, BLOCK_SIZE);
        vision_sha256_update(&ctx, inner, DIGEST_SIZE);
        vision_sha256_final(&ctx, t);
        t_len = DIGEST_SIZE;

        usize take = (remaining < DIGEST_SIZE) ? remaining : DIGEST_SIZE;
        vision_memcpy(out, t, take);
        out       += take;
        remaining -= take;
        counter++;
    }
    return 0;
}
