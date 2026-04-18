#include "config.h"
#include "vision/platform.h"

#if defined(VISION_OS_LINUX)
#  define SYS_OPEN   2
#  define SYS_READ   0
#  define SYS_CLOSE  3
#  define O_RDONLY   0
extern i64 vision_syscall3(i64, i64, i64, i64);
static i64 raw_open(const char* path, i32 flags) {
    return vision_syscall3(SYS_OPEN, (i64)path, flags, 0);
}
static isize raw_read(i64 fd, void* buf, usize n) {
    return (isize)vision_syscall3(SYS_READ, fd, (i64)buf, (i64)n);
}
static void raw_close(i64 fd) { vision_syscall3(SYS_CLOSE, fd, 0, 0); }

#elif defined(VISION_OS_MACOS)
#  define SYS_OPEN   0x2000005
#  define SYS_READ   0x2000003
#  define SYS_CLOSE  0x2000006
#  define O_RDONLY   0
extern i64 vision_syscall3(i64, i64, i64, i64);
static i64 raw_open(const char* path, i32 flags) {
    return vision_syscall3(SYS_OPEN, (i64)path, flags, 0);
}
static isize raw_read(i64 fd, void* buf, usize n) {
    return (isize)vision_syscall3(SYS_READ, fd, (i64)buf, (i64)n);
}
static void raw_close(i64 fd) { vision_syscall3(SYS_CLOSE, fd, 0, 0); }

#elif defined(VISION_OS_WIN32)
static i64 raw_open(const char* path, i32 flags) {
    (void)flags;
    typedef void* (__stdcall *PfnCreateFileA)(const char*,u32,u32,void*,u32,u32,void*);
    extern void* __stdcall GetProcAddress(void*,const char*);
    extern void* __stdcall GetModuleHandleA(const char*);
    PfnCreateFileA fn = (PfnCreateFileA)GetProcAddress(
        GetModuleHandleA("kernel32"), "CreateFileA");
    if (!fn) return -1;
    void* h = fn(path, 0x80000000UL,
                 1, (void*)0,
                 3, 0x80, (void*)0);
    return (i64)(usize)h;
}
static isize raw_read(i64 fd, void* buf, usize n) {
    typedef i32 (__stdcall *PfnReadFile)(void*,void*,u32,u32*,void*);
    extern void* __stdcall GetProcAddress(void*,const char*);
    extern void* __stdcall GetModuleHandleA(const char*);
    PfnReadFile fn = (PfnReadFile)GetProcAddress(
        GetModuleHandleA("kernel32"), "ReadFile");
    if (!fn) return -1;
    u32 read = 0;
    fn((void*)(usize)fd, buf, (u32)n, &read, (void*)0);
    return (isize)read;
}
static void raw_close(i64 fd) {
    typedef i32 (__stdcall *PfnCloseHandle)(void*);
    extern void* __stdcall GetProcAddress(void*,const char*);
    extern void* __stdcall GetModuleHandleA(const char*);
    PfnCloseHandle fn = (PfnCloseHandle)GetProcAddress(
        GetModuleHandleA("kernel32"), "CloseHandle");
    if (fn) fn((void*)(usize)fd);
}
#endif

static i32 read_file(const char* path, u8* buf, usize cap, usize* out_len) {
    i64 fd = raw_open(path, 0);
    if (fd < 0) return -1;
    usize total = 0;
    isize n;
    while ((n = raw_read(fd, buf + total, cap - total - 1)) > 0) total += (usize)n;
    raw_close(fd);
    buf[total] = 0;
    *out_len = total;
    return 0;
}

static const i8 B64[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

static usize b64_decode(const u8* in, usize in_len, u8* out, usize out_cap) {
    usize out_len = 0;
    u32 acc = 0; i32 bits = 0;
    for (usize i = 0; i < in_len && out_len < out_cap; i++) {
        i8 v = B64[in[i]];
        if (v < 0) continue;
        acc  = (acc << 6) | (u8)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[out_len++] = (u8)(acc >> bits);
            acc &= (1u << bits) - 1;
        }
    }
    return out_len;
}

i32 vision_pem_decode(const u8* pem, usize pem_len,
                       u8* der_out, usize der_cap, usize* der_len) {
    const u8* p = pem;
    const u8* end = pem + pem_len;

    while (p < end && *p != '\n') p++;
    if (p >= end) return -1;
    p++;

    const u8* body_end = p;
    while (body_end + 5 < end) {
        if (body_end[0] == '-' && body_end[1] == '-') break;
        body_end++;
    }

    *der_len = b64_decode(p, (usize)(body_end - p), der_out, der_cap);
    return (*der_len > 0) ? 0 : -1;
}

static usize cstr_len(const char* s) { usize n=0; while(s[n]) n++; return n; }

static bool8 token_eq(const u8* a, usize alen, const char* b) {
    usize blen = cstr_len(b);
    if (alen != blen) return VISION_FALSE;
    for (usize i = 0; i < alen; i++)
        if (a[i] != (u8)b[i]) return VISION_FALSE;
    return VISION_TRUE;
}

i32 vision_config_load(const char* path, VisionConfig* cfg) {
    static u8 file_buf[65536];
    usize file_len = 0;
    vision_memset(cfg, 0, sizeof(*cfg));
    cfg->port    = 8443;
    cfg->backlog = 128;
    cfg->max_connections = 4096;

    if (read_file(path, file_buf, sizeof(file_buf), &file_len) != 0)
        return -1;

    const u8* p   = file_buf;
    const u8* end = file_buf + file_len;

    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
        if (p >= end) break;
        if (*p == '#') { while (p < end && *p != '\n') p++; continue; }

        const u8* key = p;
        while (p < end && *p != '=' && *p != '\n' && *p != ' ') p++;
        usize klen = (usize)(p - key);
        while (p < end && (*p == ' ' || *p == '=')) p++;

        const u8* val = p;
        while (p < end && *p != '\n' && *p != '\r') p++;
        const u8* val_end = p;
        while (val_end > val && (*(val_end-1) == ' ' || *(val_end-1) == '\t')) val_end--;
        usize vlen = (usize)(val_end - val);

        if (klen == 0 || vlen == 0) continue;

        if (token_eq(key, klen, "port")) {
            cfg->port = (u16)(parse_u32(val, vlen));
        } else if (token_eq(key, klen, "cert")) {
            usize copy = vlen < sizeof(cfg->cert_path)-1 ? vlen : sizeof(cfg->cert_path)-1;
            vision_memcpy(cfg->cert_path, val, copy);
            cfg->cert_path[copy] = 0;
        } else if (token_eq(key, klen, "key")) {
            usize copy = vlen < sizeof(cfg->key_path)-1 ? vlen : sizeof(cfg->key_path)-1;
            vision_memcpy(cfg->key_path, val, copy);
            cfg->key_path[copy] = 0;
        } else if (token_eq(key, klen, "backlog")) {
            cfg->backlog = (i32)parse_u32(val, vlen);
        } else if (token_eq(key, klen, "max_conns")) {
            cfg->max_connections = (u32)parse_u32(val, vlen);
        }
    }
    return 0;
}

u32 parse_u32(const u8* s, usize len) {
    u32 n = 0;
    for (usize i = 0; i < len && s[i] >= '0' && s[i] <= '9'; i++)
        n = n * 10 + (s[i] - '0');
    return n;
}

i32 vision_config_load_certs(VisionConfig* cfg) {
    static u8 cert_pem[65536], key_pem[65536];
    usize plen = 0;

    if (cfg->cert_path[0]) {
        if (read_file(cfg->cert_path, cert_pem, sizeof(cert_pem), &plen) == 0) {
            vision_pem_decode(cert_pem, plen,
                              cfg->cert_der, sizeof(cfg->cert_der),
                              &cfg->cert_der_len);
        }
    }
    if (cfg->key_path[0]) {
        if (read_file(cfg->key_path, key_pem, sizeof(key_pem), &plen) == 0) {
            vision_pem_decode(key_pem, plen,
                              cfg->key_der, sizeof(cfg->key_der),
                              &cfg->key_der_len);
        }
    }
    return 0;
}
