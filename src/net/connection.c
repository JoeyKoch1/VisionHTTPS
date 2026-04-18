#include "connection.h"
#include "../mem/slab.h"
#include "vision/platform.h"

static u8          s_conn_pool_buf[sizeof(VisionConn) * VISION_MAX_CONNECTIONS];
static VisionSlab  s_conn_slab;
static i32         s_slab_ready = 0;

static void conn_slab_ensure(void) {
    if (s_slab_ready) return;
    vision_slab_init(&s_conn_slab, s_conn_pool_buf,
                     sizeof(VisionConn), VISION_MAX_CONNECTIONS);
    s_slab_ready = 1;
}

VisionConn* vision_conn_alloc(void) {
    conn_slab_ensure();
    VisionConn* c = (VisionConn*)vision_slab_alloc(&s_conn_slab);
    if (!c) return VISION_NULL;
    c->state      = CONN_STATE_ACCEPTING;
    c->read_head  = 0; c->read_tail  = 0;
    c->write_head = 0; c->write_tail = 0;
    c->tls_ctx    = VISION_NULL;
    c->next       = VISION_NULL;
    c->prev       = VISION_NULL;
    return c;
}

void vision_conn_free(VisionConn* c) {
    if (!c) return;
    vision_slab_free(&s_conn_slab, c);
}

usize vision_conn_read_available(const VisionConn* c) {
    return (c->read_tail - c->read_head + VISION_CONN_READ_BUF)
           % VISION_CONN_READ_BUF;
}

usize vision_conn_write_space(const VisionConn* c) {
    return (VISION_CONN_WRITE_BUF - 1 -
            (c->write_tail - c->write_head + VISION_CONN_WRITE_BUF)
            % VISION_CONN_WRITE_BUF);
}

isize vision_conn_drain(VisionConn* c) {
    usize space  = VISION_CONN_READ_BUF - vision_conn_read_available(c) - 1;
    if (space == 0) return 0;

    usize tail   = c->read_tail % VISION_CONN_READ_BUF;
    usize chunk  = VISION_CONN_READ_BUF - tail;
    if (chunk > space) chunk = space;

    isize n = vision_socket_read(c->fd, c->read_buf + tail, chunk);
    if (n > 0) c->read_tail += (usize)n;
    return n;
}

isize vision_conn_flush(VisionConn* c) {
    usize avail = vision_conn_read_available(c);
    if (avail == 0) return 0;

    usize head  = c->write_head % VISION_CONN_WRITE_BUF;
    usize chunk = VISION_CONN_WRITE_BUF - head;
    if (chunk > avail) chunk = avail;

    isize n = vision_socket_write(c->fd, c->write_buf + head, chunk);
    if (n > 0) c->write_head += (usize)n;
    return n;
}
