#include "vision/platform.h"

#if defined(VISION_OS_WIN32)

#include "../../src/net/connection.h"
#include "../../src/tls/handshake.h"
#include "../../src/http/parser.h"
#include "../../src/mem/slab.h"

typedef void*  HANDLE;
typedef u32    DWORD;
typedef u64    ULONG_PTR;
typedef void*  LPVOID;
typedef i32    BOOL;

#define INVALID_HANDLE_VALUE ((HANDLE)(~(usize)0))
#define INFINITE_WIN         0xFFFFFFFFUL

typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union { struct { DWORD Offset; DWORD OffsetHigh; }; LPVOID Pointer; };
    HANDLE    hEvent;
} OVERLAPPED;

typedef enum { OP_ACCEPT, OP_RECV, OP_SEND } OpType;

typedef struct {
    OVERLAPPED  ov;
    OpType      op;
    VisionConn* conn;
    u8          buf[4096];
    DWORD       buf_len;
} IocpOp;

typedef HANDLE (*PfnCreateIoCompletionPort)(HANDLE, HANDLE, ULONG_PTR, DWORD);
typedef BOOL   (*PfnGetQueuedCompletionStatus)(HANDLE, DWORD*, ULONG_PTR*, OVERLAPPED**, DWORD);
typedef BOOL   (*PfnPostQueuedCompletionStatus)(HANDLE, DWORD, ULONG_PTR, OVERLAPPED*);
typedef HANDLE (*PfnGetModuleHandleA)(const char*);
typedef LPVOID (*PfnGetProcAddress)(HANDLE, const char*);

typedef i32    (*PfnWSARecv)(u64, void*, DWORD, DWORD*, DWORD*, OVERLAPPED*, void*);
typedef i32    (*PfnWSASend)(u64, void*, DWORD, DWORD*, DWORD,  OVERLAPPED*, void*);

static PfnCreateIoCompletionPort  p_CreateIoCompletionPort;
static PfnGetQueuedCompletionStatus p_GetQueuedCompletionStatus;
static PfnWSARecv                  p_WSARecv;
static PfnWSASend                  p_WSASend;

static LPVOID resolve(const char* dll, const char* fn) {
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

#define IOCP_MAX_OPS 4096
static IocpOp s_op_pool[IOCP_MAX_OPS];
static u32    s_op_head = 0;

static IocpOp* alloc_op(OpType t, VisionConn* conn) {
    IocpOp* op = &s_op_pool[s_op_head % IOCP_MAX_OPS];
    s_op_head++;
    vision_memset(&op->ov, 0, sizeof(op->ov));
    op->op   = t;
    op->conn = conn;
    return op;
}

static void post_recv(HANDLE iocp, VisionConn* conn) {
    IocpOp* op = alloc_op(OP_RECV, conn);
    op->buf_len = sizeof(op->buf);

    struct { DWORD len; char* buf; } wsabuf = { op->buf_len, (char*)op->buf };
    DWORD flags = 0, bytes = 0;

    if (p_WSARecv) {
        p_WSARecv((u64)conn->fd, &wsabuf, 1, &bytes, &flags, &op->ov, VISION_NULL);
    }
    (void)iocp;
}

extern vision_socket_t s_listen_fd;

#define IOCP_THREADS 1

void vision_net_run(void) {
    iocp_resolve_functions();
    if (!p_CreateIoCompletionPort || !p_GetQueuedCompletionStatus) vision_exit(2);

    HANDLE iocp = p_CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                            VISION_NULL, 0, IOCP_THREADS);
    if (iocp == INVALID_HANDLE_VALUE) vision_exit(3);

    p_CreateIoCompletionPort((HANDLE)s_listen_fd, iocp, (ULONG_PTR)s_listen_fd, 0);

    for (;;) {
        DWORD      bytes     = 0;
        ULONG_PTR  key       = 0;
        OVERLAPPED* pov      = VISION_NULL;

        BOOL ok = p_GetQueuedCompletionStatus(iocp, &bytes, &key, &pov, INFINITE_WIN);
        if (!pov) continue;

        IocpOp*    op   = (IocpOp*)pov;
        VisionConn* conn = op->conn;

        if (!ok || bytes == 0) {
            if (conn) {
                vision_socket_close(conn->fd);
                vision_conn_free(conn);
            }
            continue;
        }

        switch (op->op) {
            case OP_RECV:
                if (conn && bytes > 0) {
                    usize space = VISION_CONN_READ_BUF
                                  - (conn->read_tail - conn->read_head);
                    usize take  = bytes < (DWORD)space ? bytes : (DWORD)space;
                    usize tail  = conn->read_tail % VISION_CONN_READ_BUF;
                    vision_memcpy(conn->read_buf + tail, op->buf, take);
                    conn->read_tail += take;
                    
                    if (conn->state == CONN_STATE_TLS_SHAKE) {
                        if (!conn->tls_ctx) {
                            conn->tls_ctx = vision_slab_alloc(&s_conn_slab, sizeof(TlsHandshakeCtx));
                            if (conn->tls_ctx) {
                                vision_tls_hs_init((TlsHandshakeCtx*)conn->tls_ctx, VISION_NULL, 0, VISION_NULL, 0);
                            }
                        }
                        if (conn->tls_ctx) {
                            usize avail = conn->read_tail - conn->read_head;
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
                                        usize wspace = VISION_CONN_WRITE_BUF - (conn->write_tail - conn->write_head) - 1;
                                        usize to_copy = out_len < wspace ? out_len : wspace;
                                        usize wtail = conn->write_tail % VISION_CONN_WRITE_BUF;
                                        vision_memcpy(conn->write_buf + wtail, out_buf, to_copy);
                                        conn->write_tail += to_copy;
                                    }
                                    if (vision_tls_hs_complete((TlsHandshakeCtx*)conn->tls_ctx)) {
                                        conn->state = CONN_STATE_HTTP;
                                    }
                                }
                            }
                        }
                    } else if (conn->state == CONN_STATE_HTTP) {
                        usize avail = conn->read_tail - conn->read_head;
                        if (avail > 0) {
                            usize head = conn->read_head % VISION_CONN_READ_BUF;
                            HttpRequest req;
                            HttpParseResult pr = vision_http_parse(conn->read_buf + head, avail, &req);
                            if (pr == HTTP_PARSE_COMPLETE) {
                                conn->read_head += req.consumed;
                                u8 resp_buf[4096];
                                isize resp_len = vision_http_respond_text(200, "Hello from VisionHTTPS", resp_buf, sizeof(resp_buf));
                                if (resp_len > 0) {
                                    usize wspace = VISION_CONN_WRITE_BUF - (conn->write_tail - conn->write_head) - 1;
                                    usize to_copy = (usize)resp_len < wspace ? (usize)resp_len : wspace;
                                    usize wtail = conn->write_tail % VISION_CONN_WRITE_BUF;
                                    vision_memcpy(conn->write_buf + wtail, resp_buf, to_copy);
                                    conn->write_tail += to_copy;
                                }
                            } else if (pr == HTTP_PARSE_ERROR) {
                                u8 resp_buf[512];
                                isize resp_len = vision_http_respond_400(resp_buf, sizeof(resp_buf));
                                if (resp_len > 0) {
                                    usize wspace = VISION_CONN_WRITE_BUF - (conn->write_tail - conn->write_head) - 1;
                                    usize to_copy = (usize)resp_len < wspace ? (usize)resp_len : wspace;
                                    usize wtail = conn->write_tail % VISION_CONN_WRITE_BUF;
                                    vision_memcpy(conn->write_buf + wtail, resp_buf, to_copy);
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
                        continue;
                    }
                    
                    post_recv(iocp, conn);
                }
                break;

            case OP_SEND:
                conn->write_head += bytes;
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

#endif
