#include "vision/platform.h"

extern i64 vision_syscall3(i64 nr, i64 a1, i64 a2, i64 a3);

#define SYS_READ   0x2000003
#define SYS_WRITE  0x2000004
#define SYS_CLOSE  0x2000006
#define SYS_SOCKET 0x2000061
#define SYS_BIND   0x2000068
#define SYS_LISTEN 0x2000069
#define SYS_ACCEPT 0x200001E
#define SYS_FCNTL  0x200005C

#define F_SETFL    4
#define O_NONBLOCK 0x0004

vision_socket_t vision_socket_create(i32 af, i32 type, i32 proto) {
    return (vision_socket_t)vision_syscall3(SYS_SOCKET, af, type, proto);
}
i32 vision_socket_bind(vision_socket_t s, const void* addr, u32 addrlen) {
    return (i32)vision_syscall3(SYS_BIND, s, (i64)addr, addrlen);
}
i32 vision_socket_listen(vision_socket_t s, i32 backlog) {
    return (i32)vision_syscall3(SYS_LISTEN, s, backlog, 0);
}
vision_socket_t vision_socket_accept(vision_socket_t s, void* addr, u32* addrlen) {
    return (vision_socket_t)vision_syscall3(SYS_ACCEPT, s, (i64)addr, (i64)addrlen);
}
isize vision_socket_read(vision_socket_t s, void* buf, usize len) {
    return (isize)vision_syscall3(SYS_READ, s, (i64)buf, len);
}
isize vision_socket_write(vision_socket_t s, const void* buf, usize len) {
    return (isize)vision_syscall3(SYS_WRITE, s, (i64)buf, len);
}
i32 vision_socket_close(vision_socket_t s) {
    return (i32)vision_syscall3(SYS_CLOSE, s, 0, 0);
}
i32 vision_socket_setnonblock(vision_socket_t s) {
    return (i32)vision_syscall3(SYS_FCNTL, s, F_SETFL, O_NONBLOCK);
}
