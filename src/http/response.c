#include "parser.h"
#include "vision/platform.h"

#if defined(VISION_OS_LINUX)
#  define SYS_SENDFILE  40
#  define SYS_OPEN       2
#  define SYS_FSTAT     5
#  define O_RDONLY       0
extern i64 vision_syscall4(i64, i64, i64, i64, i64);
extern i64 vision_syscall3(i64, i64, i64, i64);

static i64 open_file(const char* path) {
    return vision_syscall3(SYS_OPEN, (i64)path, O_RDONLY, 0);
}

static i64 file_size(i64 fd) {
    u8 stat_buf[144];
    vision_memset(stat_buf, 0, sizeof(stat_buf));
    if (vision_syscall3(SYS_FSTAT, fd, (i64)stat_buf, 0) < 0) return -1;
    i64 sz;
    vision_memcpy(&sz, stat_buf + 48, 8);
    return sz;
}

isize vision_sendfile(vision_socket_t out_fd, const char* path) {
    i64 in_fd = open_file(path);
    if (in_fd < 0) return -1;
    i64 size = file_size(in_fd);
    if (size <= 0) { vision_syscall3(3, in_fd, 0, 0); return -1; }
    i64 offset = 0;
    i64 sent = vision_syscall4(SYS_SENDFILE, out_fd, in_fd, (i64)&offset, size);
    vision_syscall3(3, in_fd, 0, 0);
    return (isize)sent;
}

#elif defined(VISION_OS_MACOS)
#  define SYS_SENDFILE 0x2000189
#  define SYS_OPEN     0x2000005
#  define SYS_FSTAT    0x2000339
#  define O_RDONLY     0
extern i64 vision_syscall3(i64, i64, i64, i64);

static i64 open_file(const char* path) {
    return vision_syscall3(SYS_OPEN, (i64)path, O_RDONLY, 0);
}
static i64 file_size(i64 fd) {
    u8 stat_buf[144]; vision_memset(stat_buf, 0, sizeof(stat_buf));
    if (vision_syscall3(SYS_FSTAT, fd, (i64)stat_buf, 0) < 0) return -1;
    i64 sz; vision_memcpy(&sz, stat_buf + 48, 8);
    return sz;
}
isize vision_sendfile(vision_socket_t out_fd, const char* path) {
    i64 in_fd = open_file(path);
    if (in_fd < 0) return -1;
    i64 size = file_size(in_fd);
    if (size <= 0) { vision_syscall3(0x2000006, in_fd, 0, 0); return -1; }
    i64 offset = 0, len = size;
    // syscall directly simple for now improving later  - Joey
    (void)offset; (void)len;
    vision_syscall3(0x2000006, in_fd, 0, 0);
    return (isize)size;
}

#elif defined(VISION_OS_WIN32)

typedef void*  HANDLE;
typedef u32    DWORD;
typedef u64    ULONG_PTR;
typedef i32    BOOL;
typedef i64    LARGE_INTEGER;

#define INVALID_HANDLE_VALUE ((HANDLE)(~(usize)0))
#define GENERIC_READ         ((DWORD)0x80000000)
#define OPEN_EXISTING        3
#define FILE_ATTRIBUTE_NORMAL 0x80

extern __declspec(dllimport) HANDLE __stdcall CreateFileA(const char*, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
extern __declspec(dllimport) BOOL   __stdcall GetFileSizeEx(HANDLE, LARGE_INTEGER*);
extern __declspec(dllimport) BOOL   __stdcall CloseHandle(HANDLE);
extern __declspec(dllimport) i32    __stdcall WSAGetLastError(void);

struct _OVERLAPPED;
typedef BOOL (*PfnTransmitFile)(u64, HANDLE, DWORD, DWORD, struct _OVERLAPPED*, void*, DWORD);

static LPVOID resolve(const char* dll, const char* fn) {
    extern HANDLE __stdcall GetModuleHandleA(const char*);
    extern LPVOID __stdcall GetProcAddress(HANDLE, const char*);
    HANDLE h = GetModuleHandleA(dll);
    if (!h) return VISION_NULL;
    return GetProcAddress(h, fn);
}

isize vision_sendfile(vision_socket_t out_fd, const char* path) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, VISION_NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, VISION_NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;
    
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hFile, &sz)) {
        CloseHandle(hFile);
        return -1;
    }
    if (sz <= 0) {
        CloseHandle(hFile);
        return -1;
    }
    
    PfnTransmitFile pTransmitFile = (PfnTransmitFile)resolve("mswsock", "TransmitFile");
    if (!pTransmitFile) {
        u8 buf[8192];
        extern __declspec(dllimport) BOOL __stdcall ReadFile(HANDLE, void*, DWORD, DWORD*, void*);
        DWORD total_sent = 0;
        DWORD read = 0;
        while (ReadFile(hFile, buf, sizeof(buf), &read, VISION_NULL) && read > 0) {
            extern i32 __stdcall send(u64, const void*, i32, i32);
            i32 sent = send(out_fd, buf, (i32)read, 0);
            if (sent <= 0) {
                CloseHandle(hFile);
                return -1;
            }
            total_sent += sent;
        }
        CloseHandle(hFile);
        return (isize)total_sent;
    }
    
    BOOL ok = pTransmitFile(out_fd, hFile, (DWORD)sz, 0, VISION_NULL, VISION_NULL, 0);
    CloseHandle(hFile);
    if (!ok) return -1;
    return (isize)sz;
}
#endif

typedef struct { const char* ext; const char* mime; } MimeEntry;
static const MimeEntry MIME_TABLE[] = {
    { "html", "text/html; charset=utf-8"  },
    { "htm",  "text/html; charset=utf-8"  },
    { "css",  "text/css"                  },
    { "js",   "application/javascript"    },
    { "json", "application/json"          },
    { "png",  "image/png"                 },
    { "jpg",  "image/jpeg"                },
    { "jpeg", "image/jpeg"                },
    { "gif",  "image/gif"                 },
    { "svg",  "image/svg+xml"             },
    { "ico",  "image/x-icon"              },
    { "woff2","font/woff2"                },
    { "woff", "font/woff"                 },
    { "txt",  "text/plain"                },
    { "xml",  "application/xml"           },
    { "pdf",  "application/pdf"           },
    { (const char*)0, (const char*)0 }
};

static const char* mime_for_path(const u8* path, usize path_len) {
    i64 dot = (i64)path_len - 1;
    while (dot >= 0 && path[dot] != '.') dot--;
    if (dot < 0) return "application/octet-stream";
    const u8* ext = path + dot + 1;
    usize ext_len = path_len - (usize)dot - 1;

    for (const MimeEntry* m = MIME_TABLE; m->ext; m++) {
        usize ml = 0; while (m->ext[ml]) ml++;
        if (ml != ext_len) continue;
        bool8 eq = VISION_TRUE;
        for (usize i = 0; i < ext_len; i++)
            if ((ext[i] | 32) != (u8)m->ext[i]) { eq = VISION_FALSE; break; }
        if (eq) return m->mime;
    }
    return "application/octet-stream";
}

static char s_webroot[256];
static usize s_webroot_len = 0;

void vision_http_set_webroot(const char* root) {
    usize len = 0; while (root[len]) len++;
    usize copy = len < 255 ? len : 255;
    vision_memcpy(s_webroot, root, copy);
    s_webroot[copy] = 0;
    s_webroot_len   = copy;
}

isize vision_http_serve_static(const HttpRequest* req, u8* out, usize cap) {
    static u8 path_buf[512];
    usize plen = 0;
    vision_memcpy(path_buf + plen, s_webroot, s_webroot_len); plen += s_webroot_len;

    for (usize i = 0; i + 1 < req->path_len; i++) {
        if (req->path[i] == '.' && req->path[i+1] == '.') {
            return vision_http_respond_400(out, cap);
        }
    }
    usize copy = req->path_len < (512 - plen - 1) ? req->path_len : (512 - plen - 1);
    vision_memcpy(path_buf + plen, req->path, copy);
    plen += copy;

    if (plen > 0 && path_buf[plen-1] == '/') {
        const char* idx = "index.html";
        usize ilen = 10;
        if (plen + ilen < 511) {
            vision_memcpy(path_buf + plen, idx, ilen);
            plen += ilen;
        }
    }
    path_buf[plen] = 0;

    const char* mime = mime_for_path(req->path, req->path_len);

    usize off = 0;
    const char* status = "HTTP/1.1 200 OK\r\n";
    usize sl = 17; vision_memcpy(out + off, status, sl); off += sl;

    const char* ct_hdr = "Content-Type: ";
    usize ctl = 14; vision_memcpy(out + off, ct_hdr, ctl); off += ctl;
    usize ml = 0; while (mime[ml]) ml++;
    vision_memcpy(out + off, mime, ml); off += ml;
    out[off++] = '\r'; out[off++] = '\n';

    const char* svr = "Server: Vision/0.1\r\n\r\n";
    usize svl = 22; vision_memcpy(out + off, svr, svl); off += svl;

    if (off >= cap) return -1;

    vision_sendfile(VISION_INVALID_SOCKET, (const char*)path_buf);

    return (isize)off;
}
