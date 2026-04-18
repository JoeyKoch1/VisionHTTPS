/*
 * src/net/event_loop.c
 * Cross-platform event loop entry points.
 *
 * Linux  → epoll
 * macOS  → kqueue
 * Win32  → IOCP  (scaffold — full impl in next sprint)
 *
 * vision_net_init()  — create listen socket, bind, listen
 * vision_net_run()   — enter event loop, never returns
 */
#include "connection.h"
#include "vision/platform.h"

/* ── Address family constants (same as kernel, no headers needed) ──────── */
#define AF_INET      2
#define SOCK_STREAM  1
#define IPPROTO_TCP  6
#define SOL_SOCKET   1
#define SO_REUSEADDR 2

/* sockaddr_in — hand-rolled, matches kernel ABI on all three platforms */
typedef struct {
    u16 sin_family;
    u16 sin_port;      /* network byte order */
    u8  sin_addr[4];   /* IPv4 in network byte order */
    u8  _pad[8];
} vision_sockaddr_in;

static VISION_INLINE u16 hton16(u16 v) {
    return (u16)((v << 8) | (v >> 8));
}

/* ── Listen socket (shared across platforms) ───────────────────────────── */
static vision_socket_t s_listen_fd = VISION_INVALID_SOCKET;

int vision_net_init(u16 port) {
    vision_socket_t fd = vision_socket_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == VISION_INVALID_SOCKET) return -1;

    i32 reuse = 1;
    /* SO_REUSEADDR: we do this via platform socket API for now */
    (void)reuse; /* TODO: add vision_socket_setsockopt() */

    vision_sockaddr_in addr;
    vision_memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = hton16(port);
    /* INADDR_ANY = 0.0.0.0 — already zero from memset */

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

/* ── Platform event loops ──────────────────────────────────────────────── */

#if defined(VISION_OS_LINUX)
/* ── epoll numbers (Linux x86-64) ──── */
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

/* Matches kernel struct epoll_event (packed!) */
typedef struct __attribute__((packed)) {
    u32 events;
    u64 data;   /* we store the fd here */
} vision_epoll_event;

/* Raw syscall stubs from platform/linux/syscall.asm */
extern i64 vision_syscall1(i64 nr, i64 a1);
extern i64 vision_syscall3(i64 nr, i64 a1, i64 a2, i64 a3);
extern i64 vision_syscall4(i64 nr, i64 a1, i64 a2, i64 a3, i64 a4);

#define VISION_MAX_EVENTS 256

void vision_net_run(void) {
    i64 epfd = vision_syscall1(SYS_EPOLL_CREATE1, 0);
    if (epfd < 0) vision_exit(1);

    /* Register listen socket */
    vision_epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data   = (u64)s_listen_fd;
    vision_syscall4(SYS_EPOLL_CTL, epfd, EPOLL_CTL_ADD, s_listen_fd, (i64)&ev);

    vision_epoll_event events[VISION_MAX_EVENTS];

    for (;;) {
        i64 n = vision_syscall4(SYS_EPOLL_WAIT, epfd,
                                (i64)events, VISION_MAX_EVENTS, -1);
        if (n < 0) continue;   /* EINTR — loop */

        for (i64 i = 0; i < n; i++) {
            vision_socket_t fd = (vision_socket_t)events[i].data;

            if (fd == s_listen_fd) {
                /* Accept all pending connections */
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
                /* Data/write-ready on a connection */
                VisionConn* conn = (VisionConn*)(usize)events[i].data;
                u32 evs = events[i].events;

                if (evs & (EPOLLERR | EPOLLHUP)) {
                    vision_socket_close(conn->fd);
                    vision_conn_free(conn);
                    continue;
                }
                if (evs & EPOLLIN)  vision_conn_drain(conn);
                if (evs & EPOLLOUT) vision_conn_flush(conn);

                /* TODO: dispatch to TLS / HTTP handler based on conn->state */
            }
        }
    }
}

#elif defined(VISION_OS_MACOS)
/* kqueue scaffold — full impl next sprint */
void vision_net_run(void) {
    /* TODO: kqueue event loop */
    vision_exit(99);
}

#elif defined(VISION_OS_WIN32)
/* IOCP scaffold — full impl next sprint */
void vision_net_run(void) {
    /* TODO: IOCP event loop */
    vision_exit(99);
}
#endif
