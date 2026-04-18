#ifndef VISION_NET_CONNECTION_H
#define VISION_NET_CONNECTION_H

#include "vision/platform.h"

/* ── Sizes ────────────────────────────────────────────────────────────── */
#define VISION_CONN_READ_BUF    (16 * 1024)   /* 16 KiB per-conn read buf  */
#define VISION_CONN_WRITE_BUF   (16 * 1024)   /* 16 KiB per-conn write buf */
#define VISION_MAX_CONNECTIONS  4096

/* ── Connection state machine ─────────────────────────────────────────── */
typedef enum {
    CONN_STATE_FREE       = 0,
    CONN_STATE_ACCEPTING  = 1,
    CONN_STATE_TLS_SHAKE  = 2,   /* mid TLS handshake               */
    CONN_STATE_HTTP       = 3,   /* TLS up, processing HTTP          */
    CONN_STATE_CLOSING    = 4,
} ConnState;

/* ── Per-connection struct ────────────────────────────────────────────── */
typedef struct VisionConn {
    vision_socket_t fd;
    ConnState       state;

    /* I/O ring buffers (flat arrays — no dynamic alloc) */
    u8   read_buf[VISION_CONN_READ_BUF];
    usize read_head;
    usize read_tail;

    u8   write_buf[VISION_CONN_WRITE_BUF];
    usize write_head;
    usize write_tail;

    /* TLS state pointer — allocated from slab in tls module */
    void* tls_ctx;

    /* Linked list for the event loop's active connection set */
    struct VisionConn* next;
    struct VisionConn* prev;
} VisionConn;

#ifdef __cplusplus
extern "C" {
#endif

int  vision_net_init(u16 port);
void vision_net_run(void);    /* main event loop — never returns */

#ifdef __cplusplus
}
#endif

#endif /* VISION_NET_CONNECTION_H */
