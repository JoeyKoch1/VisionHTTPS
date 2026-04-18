#include "vision/platform.h"

extern i64 vision_syscall3(i64 nr, i64 a1, i64 a2, i64 a3);
extern i64 vision_syscall4(i64 nr, i64 a1, i64 a2, i64 a3, i64 a4);

#define SYS_READ     0
#define SYS_WRITE    1
#define SYS_CLOSE    3
#define SYS_SOCKET   41
#define SYS_ACCEPT   43
#define SYS_BIND     49
#define SYS_LISTEN   50
#define SYS_FCNTL    72

#define F_SETFL      4
#define O_NONBLOCK   2048

vision_socket_t vision_socket_create(i32 af, i32 type, i32 proto) {
    return (vision_socket_t)vision_syscall3(SYS_SOCKET, af, type, proto);
}

i32 vision_socket_bind(vision_socket_t s, const void* addr, u32 addrlen) {
    return (i32)vision_syscall3(SYS_BIND, (i64)s, (i64)addr, (i64)addrlen);
}

i32 vision_socket_listen(vision_socket_t s, i32 backlog) {
    return (i32)vision_syscall3(SYS_LISTEN, (i64)s, backlog, 0);
}

vision_socket_t vision_socket_accept(vision_socket_t s, void* addr, u32* addrlen) {
    return (vision_socket_t)vision_syscall3(SYS_ACCEPT, (i64)s, (i64)addr, (i64)addrlen);
}

isize vision_socket_read(vision_socket_t s, void* buf, usize len) {
    return (isize)vision_syscall3(SYS_READ, (i64)s, (i64)buf, (i64)len);
}

isize vision_socket_write(vision_socket_t s, const void* buf, usize len) {
    return (isize)vision_syscall3(SYS_WRITE, (i64)s, (i64)buf, (i64)len);
}

i32 vision_socket_close(vision_socket_t s) {
    return (i32)vision_syscall3(SYS_CLOSE, (i64)s, 0, 0);
}

i32 vision_socket_setnonblock(vision_socket_t s) {
    return (i32)vision_syscall3(SYS_FCNTL, (i64)s, F_SETFL, O_NONBLOCK);
}
