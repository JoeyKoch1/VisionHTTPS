#include "connection.h"
#include "../tls/handshake.h"
#include "../http/parser.h"
#include "../mem/slab.h"
#include "vision/platform.h"

#define AF_INET      2
#define SOCK_STREAM  1
#define IPPROTO_TCP  6
#define SOL_SOCKET   1
#define SO_REUSEADDR 2

typedef struct {
    u16 sin_family;
    u16 sin_port;
    u8  sin_addr[4];
    u8  _pad[8];
} vision_sockaddr_in;

static VISION_INLINE u16 hton16(u16 v) {
    return (u16)((v << 8) | (v >> 8));
}

static vision_socket_t s_listen_fd = VISION_INVALID_SOCKET;

int vision_net_init(u16 port) {
    vision_socket_t fd = vision_socket_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == VISION_INVALID_SOCKET) return -1;

    i32 reuse = 1;
    vision_socket_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    vision_sockaddr_in addr;
    vision_memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = hton16(port);

    if (vision_socket_bind(fd, &addr, sizeof(addr)) != 0) {
        vision_socket_close(fd);
        return -2;
    }

    if (vision_socket_listen(fd, 128) != 0) {
        vision_socket_close(fd);
        return -3;
    }

    if (vision_socket_setnonblock(fd) != 0) {
        vision_socket_close(fd);
        return -4;
    }

    s_listen_fd = fd;
    return 0;
}

#if defined(VISION_OS_LINUX)
#define SYS_EPOLL_CREATE1  291
#define SYS_EPOLL_CTL      233
#define SYS_EPOLL_WAIT     232
#define EPOLLIN            0x00000001u
#define EPOLLOUT           0x00000004u
#define EPOLLERR           0x00000008u
#define EPOLLHUP           0x00000010u
#define EPOLLET            0x80000000u
#define EPOLL_CTL_ADD      1
#define EPOLL_CTL_MOD      2
#define EPOLL_CTL_DEL      3

typedef struct __attribute__((packed)) {
    u32 events;
    u64 data;
} vision_epoll_event;

extern i64 vision_syscall1(i64 nr, i64 a1);
extern i64 vision_syscall3(i64 nr, i64 a1, i64 a2, i64 a3);
extern i64 vision_syscall4(i64 nr, i64 a1, i64 a2, i64 a3, i64 a4);

#define VISION_MAX_EVENTS 256

void vision_net_run(void) {
    i64 epfd = vision_syscall1(SYS_EPOLL_CREATE1, 0);
    if (epfd < 0) vision_exit(1);

    vision_epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data   = (u64)s_listen_fd;
    vision_syscall4(SYS_EPOLL_CTL, epfd, EPOLL_CTL_ADD, s_listen_fd, (i64)&ev);

    vision_epoll_event events[VISION_MAX_EVENTS];

    for (;;) {
        i64 n = vision_syscall4(SYS_EPOLL_WAIT, epfd,
                                (i64)events, VISION_MAX_EVENTS, -1);
        if (n < 0) continue;

        for (i64 i = 0; i < n; i++) {
            vision_socket_t fd = (vision_socket_t)events[i].data;

            if (fd == s_listen_fd) {
                for (;;) {
                    vision_sockaddr_in peer;
                    u32 plen = sizeof(peer);
                    vision_socket_t cfd = vision_socket_accept(
                        s_listen_fd, &peer, &plen);
                    if (cfd == VISION_INVALID_SOCKET) break;

                    vision_socket_setnonblock(cfd);
                    VisionConn* conn = vision_conn_alloc();
                    if (!conn) {
                        vision_socket_close(cfd);
                        continue;
                    }
                    conn->fd    = cfd;
                    conn->state = CONN_STATE_TLS_SHAKE;

                    vision_epoll_event cev;
                    cev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLHUP;
                    cev.data   = (u64)conn;
                    vision_syscall4(SYS_EPOLL_CTL, epfd,
                                    EPOLL_CTL_ADD, cfd, (i64)&cev);
                }
            } else {
                VisionConn* conn = (VisionConn*)(usize)events[i].data;
                u32 evs = events[i].events;

                if (evs & (EPOLLERR | EPOLLHUP)) {
                    vision_socket_close(conn->fd);
                    vision_conn_free(conn);
                    continue;
                }
                if (evs & EPOLLIN)  vision_conn_drain(conn);
                if (evs & EPOLLOUT) vision_conn_flush(conn);

                if (conn->state == CONN_STATE_TLS_SHAKE) {
                    if (!conn->tls_ctx) {
                        conn->tls_ctx = vision_slab_alloc(&s_conn_slab, sizeof(TlsHandshakeCtx));
                        if (conn->tls_ctx) {
                            vision_tls_hs_init((TlsHandshakeCtx*)conn->tls_ctx, VISION_NULL, 0, VISION_NULL, 0);
                        }
                    }
                    if (conn->tls_ctx) {
                        usize avail = vision_conn_read_available(conn);
                        if (avail > 0) {
                            u8 out_buf[4096];
                            usize out_len = sizeof(out_buf);
                            usize head = conn->read_head % VISION_CONN_READ_BUF;
                            i32 hs_result = vision_tls_hs_consume((TlsHandshakeCtx*)conn->tls_ctx,
                                                                   conn->read_buf + head, avail,
                                                                   out_buf, &out_len);
                            if (hs_result < 0) {
                                conn->state = CONN_STATE_CLOSING;
                            } else {
                                conn->read_head += avail;
                                if (out_len > 0) {
                                    usize space = vision_conn_write_space(conn);
                                    usize to_copy = out_len < space ? out_len : space;
                                    usize tail = conn->write_tail % VISION_CONN_WRITE_BUF;
                                    vision_memcpy(conn->write_buf + tail, out_buf, to_copy);
                                    conn->write_tail += to_copy;
                                }
                                if (vision_tls_hs_complete((TlsHandshakeCtx*)conn->tls_ctx)) {
                                    conn->state = CONN_STATE_HTTP;
                                }
                            }
                        }
                    }
                } else if (conn->state == CONN_STATE_HTTP) {
                    usize avail = vision_conn_read_available(conn);
                    if (avail > 0) {
                        usize head = conn->read_head % VISION_CONN_READ_BUF;
                        HttpRequest req;
                        HttpParseResult pr = vision_http_parse(conn->read_buf + head, avail, &req);
                        if (pr == HTTP_PARSE_COMPLETE) {
                            conn->read_head += req.consumed;
                            u8 resp_buf[4096];
                            isize resp_len = vision_http_respond_text(200, "Hello from VisionHTTPS", resp_buf, sizeof(resp_buf));
                            if (resp_len > 0) {
                                usize space = vision_conn_write_space(conn);
                                usize to_copy = (usize)resp_len < space ? (usize)resp_len : space;
                                usize tail = conn->write_tail % VISION_CONN_WRITE_BUF;
                                vision_memcpy(conn->write_buf + tail, resp_buf, to_copy);
                                conn->write_tail += to_copy;
                            }
                        } else if (pr == HTTP_PARSE_ERROR) {
                            u8 resp_buf[512];
                            isize resp_len = vision_http_respond_400(resp_buf, sizeof(resp_buf));
                            if (resp_len > 0) {
                                usize space = vision_conn_write_space(conn);
                                usize to_copy = (usize)resp_len < space ? (usize)resp_len : space;
                                usize tail = conn->write_tail % VISION_CONN_WRITE_BUF;
                                vision_memcpy(conn->write_buf + tail, resp_buf, to_copy);
                                conn->write_tail += to_copy;
                            }
                            conn->state = CONN_STATE_CLOSING;
                        }
                    }
                } else if (conn->state == CONN_STATE_CLOSING) {
                    vision_socket_close(conn->fd);
                    if (conn->tls_ctx) {
                        vision_slab_free(&s_conn_slab, conn->tls_ctx);
                        conn->tls_ctx = VISION_NULL;
                    }
                    vision_conn_free(conn);
                }
        }
    }
}

#elif defined(VISION_OS_MACOS)
void vision_net_run(void);

#elif defined(VISION_OS_WIN32)
void vision_net_run(void);
#endif
