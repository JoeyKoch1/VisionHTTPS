#include "../src/crypto/aes_gcm.h"
#include "vision/platform.h"

int test_aes_gcm(void) {
#if defined(VISION_ARCH_X86_64)
    static const u8 key[16] = {
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    };
    static const u8 nonce[12] = {
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
    };
    static const u8 expected_tag[16] = {
        0x58,0xe2,0xfc,0xce, 0xfa,0x7e,0x30,0x61,
        0x36,0x7f,0x1d,0x57, 0xa4,0xe7,0x45,0x5a,
    };

    VisionAesGcmCtx ctx;
    if (vision_aesgcm_init(&ctx, key, 16) != 0) return 1;

    u8 tag[16];
    if (vision_aesgcm_seal(&ctx, nonce,
                            (const u8*)"", 0,
                            (const u8*)"", 0,
                            (u8*)"", tag) != 0) return 2;

    if (vision_memcmp(tag, expected_tag, 16) != 0) return 3;

    if (vision_aesgcm_open(&ctx, nonce,
                            (const u8*)"", 0,
                            (const u8*)"", 0,
                            tag, (u8*)"") != 0) return 4;

    u8 bad[16];
    vision_memcpy(bad, tag, 16);
    bad[7] ^= 0x01;
    if (vision_aesgcm_open(&ctx, nonce,
                            (const u8*)"", 0,
                            (const u8*)"", 0,
                            bad, (u8*)"") == 0) return 5;

    return 0;
#else
    return 0;
#endif
}
