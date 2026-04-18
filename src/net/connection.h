#ifndef VISION_NET_CONNECTION_H
#define VISION_NET_CONNECTION_H

#include "vision/platform.h"

#define VISION_CONN_READ_BUF    (16 * 1024)
#define VISION_CONN_WRITE_BUF   (16 * 1024)
#define VISION_MAX_CONNECTIONS  4096

typedef enum {
    CONN_STATE_FREE       = 0,
    CONN_STATE_ACCEPTING  = 1,
    CONN_STATE_TLS_SHAKE  = 2,
    CONN_STATE_HTTP       = 3,
    CONN_STATE_CLOSING    = 4,
} ConnState;

typedef struct VisionConn {
    vision_socket_t fd;
    ConnState       state;

    u8   read_buf[VISION_CONN_READ_BUF];
    usize read_head;
    usize read_tail;

    u8   write_buf[VISION_CONN_WRITE_BUF];
    usize write_head;
    usize write_tail;

    void* tls_ctx;

    struct VisionConn* next;
    struct VisionConn* prev;
} VisionConn;

#ifdef __cplusplus
extern "C" {
#endif

int  vision_net_init(u16 port);
void vision_net_run(void);

#ifdef __cplusplus
}
#endif

#endif
