#include "vision/platform.h"

#if defined(VISION_OS_MACOS)

#include "../../src/net/connection.h"

#define SYS_KQUEUE       362
#define SYS_KEVENT       363
#define SYS_CLOSE   0x2000006

#define EVFILT_READ   (-1)
#define EVFILT_WRITE  (-2)

#define EV_ADD        0x0001
#define EV_DELETE     0x0002
#define EV_ENABLE     0x0004
#define EV_DISABLE    0x0008
#define EV_EOF        0x8000
#define EV_ERROR      0x4000
#define EV_CLEAR      0x0020

typedef struct {
    u64 ident;
    i16 filter;
    u16 flags;
    u32 fflags;
    i64 data;
    void* udata;
} KEvent;

extern i64 vision_syscall1(i64 nr, i64 a1);
extern i64 vision_syscall6(i64 nr, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6);

static i64 sys_kqueue(void) {
    return vision_syscall1(SYS_KQUEUE, 0);
}

static i64 sys_kevent(i64 kq,
                       const KEvent* chlist, i64 nch,
                       KEvent*       evlist, i64 nev,
                       void*         timeout) {
    return vision_syscall6(SYS_KEVENT,
                            kq, (i64)chlist, nch,
                            (i64)evlist, nev, (i64)timeout);
}

extern vision_socket_t s_listen_fd;

#define VISION_MAX_EVENTS 256

void vision_net_run(void) {
    i64 kq = sys_kqueue();
    if (kq < 0) vision_exit(1);

    KEvent change;
    change.ident  = (u64)s_listen_fd;
    change.filter = EVFILT_READ;
    change.flags  = EV_ADD | EV_ENABLE;
    change.fflags = 0; change.data = 0; change.udata = VISION_NULL;
    sys_kevent(kq, &change, 1, VISION_NULL, 0, VISION_NULL);

    KEvent events[VISION_MAX_EVENTS];
    vision_sockaddr_in peer;

    for (;;) {
        i64 n = sys_kevent(kq, VISION_NULL, 0, events, VISION_MAX_EVENTS, VISION_NULL);
        if (n < 0) continue;

        for (i64 i = 0; i < n; i++) {
            KEvent* ev = &events[i];

            if ((vision_socket_t)ev->ident == s_listen_fd) {
                for (;;) {
                    u32 plen = 16;
                    vision_socket_t cfd = vision_socket_accept(
                        s_listen_fd, &peer, &plen);
                    if (cfd == VISION_INVALID_SOCKET) break;

                    vision_socket_setnonblock(cfd);
                    VisionConn* conn = vision_conn_alloc();
                    if (!conn) { vision_socket_close(cfd); continue; }
                    conn->fd    = cfd;
                    conn->state = CONN_STATE_TLS_SHAKE;

                    KEvent ch[2];
                    ch[0].ident=ch[1].ident=(u64)cfd;
                    ch[0].filter=EVFILT_READ;  ch[0].flags=EV_ADD|EV_ENABLE|EV_CLEAR;
                    ch[0].fflags=0; ch[0].data=0; ch[0].udata=conn;
                    ch[1].filter=EVFILT_WRITE; ch[1].flags=EV_ADD|EV_ENABLE|EV_CLEAR;
                    ch[1].fflags=0; ch[1].data=0; ch[1].udata=conn;
                    sys_kevent(kq, ch, 2, VISION_NULL, 0, VISION_NULL);
                }
            } else {
                VisionConn* conn = (VisionConn*)ev->udata;
                if (!conn) continue;

                if (ev->flags & (EV_EOF | EV_ERROR)) {
                    vision_socket_close(conn->fd);
                    vision_conn_free(conn);
                    continue;
                }
                if (ev->filter == EVFILT_READ)  vision_conn_drain(conn);
                if (ev->filter == EVFILT_WRITE) vision_conn_flush(conn);
                // TODO: dispatch to TLS/HTTP handler
            }
        }
    }
}

#endif
