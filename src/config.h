#ifndef VISION_CONFIG_H
#define VISION_CONFIG_H

#include "vision/platform.h"

typedef struct {
    u16  port;
    i32  backlog;
    u32  max_connections;

    char cert_path[256];
    char key_path[256];

    u8   cert_der[8192];
    usize cert_der_len;

    u8   key_der[4096];
    usize key_der_len;
} VisionConfig;

#ifdef __cplusplus
extern "C" {
#endif

i32  vision_config_load(const char* path, VisionConfig* cfg);
i32  vision_config_load_certs(VisionConfig* cfg);

i32  vision_pem_decode(const u8* pem, usize pem_len,
                        u8* der_out, usize der_cap, usize* der_len);

u32  parse_u32(const u8* s, usize len);

#ifdef __cplusplus
}
#endif

#endif
