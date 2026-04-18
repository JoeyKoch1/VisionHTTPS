/*
 * platform/win32/iocp.c
 * Windows I/O Completion Port (IOCP) event loop.
 * Phase 1: uses Win32 API via GetProcAddress — no import libs for WS2.
 * We dynamically resolve all functions so we can eventually replace them
 * with direct NT syscall stubs without changing call sites.
 */
#include "vision/platform.h"

#if defined(VISION_OS_WIN32)

#include "../../src/net/connection.h"

/* ── Minimal Win32 type redeclarations ───────────────────────────────── */
typedef void*  HANDLE;
typedef u32    DWORD;
typedef u64    ULONG_PTR;
typedef void*  LPVOID;
typedef i32    BOOL;

#define INVALID_HANDLE_VALUE ((HANDLE)(~(usize)0))
#define INFINITE_WIN         0xFFFFFFFFUL

/* OVERLAPPED — the core IOCP structure */
typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union { struct { DWORD Offset; DWORD OffsetHigh; }; LPVOID Pointer; };
    HANDLE    hEvent;
} OVERLAPPED;

/* Per-operation context (extends OVERLAPPED — must be first field) */
typedef enum { OP_ACCEPT, OP_RECV, OP_SEND } OpType;

typedef struct {
    OVERLAPPED  ov;       /* MUST be first */
    OpType      op;
    VisionConn* conn;
    u8          buf[4096];
    DWORD       buf_len;
} IocpOp;

/* ── Kernel32 function pointers (resolved at startup) ────────────────── */
typedef HANDLE (*PfnCreateIoCompletionPort)(HANDLE, HANDLE, ULONG_PTR, DWORD);
typedef BOOL   (*PfnGetQueuedCompletionStatus)(HANDLE, DWORD*, ULONG_PTR*, OVERLAPPED**, DWORD);
typedef BOOL   (*PfnPostQueuedCompletionStatus)(HANDLE, DWORD, ULONG_PTR, OVERLAPPED*);
typedef HANDLE (*PfnGetModuleHandleA)(const char*);
typedef LPVOID (*PfnGetProcAddress)(HANDLE, const char*);

/* ws2_32 function pointers */
typedef i32    (*PfnWSARecv)(u64, void*, DWORD, DWORD*, DWORD*, OVERLAPPED*, void*);
typedef i32    (*PfnWSASend)(u64, void*, DWORD, DWORD*, DWORD,  OVERLAPPED*, void*);

static PfnCreateIoCompletionPort  p_CreateIoCompletionPort;
static PfnGetQueuedCompletionStatus p_GetQueuedCompletionStatus;
static PfnWSARecv                  p_WSARecv;
static PfnWSASend                  p_WSASend;

/* Resolve via inline asm GetModuleHandle → GetProcAddress */
static LPVOID resolve(const char* dll, const char* fn) {
    /* Use __implicit__ import of kernel32 for bootstrap only */
    extern HANDLE __stdcall GetModuleHandleA(const char*);
    extern LPVOID __stdcall GetProcAddress(HANDLE, const char*);
    HANDLE h = GetModuleHandleA(dll);
    if (!h) return VISION_NULL;
    return GetProcAddress(h, fn);
}

static void iocp_resolve_functions(void) {
    p_CreateIoCompletionPort   = (PfnCreateIoCompletionPort)  resolve("kernel32", "CreateIoCompletionPort");
    p_GetQueuedCompletionStatus= (PfnGetQueuedCompletionStatus)resolve("kernel32", "GetQueuedCompletionStatus");
    p_WSARecv = (PfnWSARecv)resolve("ws2_32", "WSARecv");
    p_WSASend = (PfnWSASend)resolve("ws2_32", "WSASend");
}

/* ── Static op pool (no heap) ────────────────────────────────────────── */
#define IOCP_MAX_OPS 4096
static IocpOp s_op_pool[IOCP_MAX_OPS];
static u32    s_op_head = 0;

static IocpOp* alloc_op(OpType t, VisionConn* conn) {
    /* Simple round-robin pool — safe for fixed connection count */
    IocpOp* op = &s_op_pool[s_op_head % IOCP_MAX_OPS];
    s_op_head++;
    vision_memset(&op->ov, 0, sizeof(op->ov));
    op->op   = t;
    op->conn = conn;
    return op;
}

/* ── Post a WSARecv on a connection ──────────────────────────────────── */
static void post_recv(HANDLE iocp, VisionConn* conn) {
    IocpOp* op = alloc_op(OP_RECV, conn);
    op->buf_len = sizeof(op->buf);

    /* WSABUF */
    struct { DWORD len; char* buf; } wsabuf = { op->buf_len, (char*)op->buf };
    DWORD flags = 0, bytes = 0;

    if (p_WSARecv) {
        p_WSARecv((u64)conn->fd, &wsabuf, 1, &bytes, &flags, &op->ov, VISION_NULL);
    }
    (void)iocp;
}

extern vision_socket_t s_listen_fd;

#define IOCP_THREADS 1  /* single-threaded for now */

void vision_net_run(void) {
    iocp_resolve_functions();
    if (!p_CreateIoCompletionPort || !p_GetQueuedCompletionStatus) vision_exit(2);

    /* Create IOCP */
    HANDLE iocp = p_CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                            VISION_NULL, 0, IOCP_THREADS);
    if (iocp == INVALID_HANDLE_VALUE) vision_exit(3);

    /* Associate listen socket — accept loop runs separately on Windows */
    p_CreateIoCompletionPort((HANDLE)s_listen_fd, iocp, (ULONG_PTR)s_listen_fd, 0);

    for (;;) {
        DWORD      bytes     = 0;
        ULONG_PTR  key       = 0;
        OVERLAPPED* pov      = VISION_NULL;

        BOOL ok = p_GetQueuedCompletionStatus(iocp, &bytes, &key, &pov, INFINITE_WIN);
        if (!pov) continue;

        IocpOp*    op   = (IocpOp*)pov;   /* safe: OVERLAPPED is first field */
        VisionConn* conn = op->conn;

        if (!ok || bytes == 0) {
            /* Connection closed or error */
            if (conn) {
                vision_socket_close(conn->fd);
                vision_conn_free(conn);
            }
            continue;
        }

        switch (op->op) {
            case OP_RECV:
                /* Copy received data into connection read ring buffer */
                if (conn && bytes > 0) {
                    usize space = VISION_CONN_READ_BUF
                                  - (conn->read_tail - conn->read_head);
                    usize take  = bytes < (DWORD)space ? bytes : (DWORD)space;
                    usize tail  = conn->read_tail % VISION_CONN_READ_BUF;
                    vision_memcpy(conn->read_buf + tail, op->buf, take);
                    conn->read_tail += take;
                    /* TODO: dispatch TLS / HTTP */
                    post_recv(iocp, conn); /* re-arm */
                }
                break;

            case OP_SEND:
                conn->write_head += bytes;
                /* Re-post send if more data pending */
                if (conn->write_tail > conn->write_head) {
                    IocpOp* sop = alloc_op(OP_SEND, conn);
                    usize head = conn->write_head % VISION_CONN_WRITE_BUF;
                    usize avail= conn->write_tail - conn->write_head;
                    usize chunk= VISION_CONN_WRITE_BUF - head;
                    if (chunk > avail) chunk = avail;
                    vision_memcpy(sop->buf, conn->write_buf + head, chunk);
                    sop->buf_len = (DWORD)chunk;
                    struct { DWORD len; char* buf; } wsabuf = { sop->buf_len, (char*)sop->buf };
                    DWORD sent = 0;
                    if (p_WSASend)
                        p_WSASend((u64)conn->fd, &wsabuf, 1, &sent, 0, &sop->ov, VISION_NULL);
                }
                break;

            case OP_ACCEPT:
                break;
        }
    }
}

#endif /* VISION_OS_WIN32 */
