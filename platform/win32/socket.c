/*
 * platform/win32/socket.c
 *
 * Phase 1 (bootstrap):  uses Winsock2 behind a thin shim so we can test
 *                        the upper layers on Windows immediately.
 * Phase 2 (zero-extern): replace WSA calls with direct NtCreateFile /
 *                         NtDeviceIoControlFile (AFD driver) via our MASM stubs.
 *
 * This file deliberately avoids #include <winsock2.h> to stay dependency-light.
 * We forward-declare only what we need using the raw Win32 types.
 */
#include "vision/platform.h"

/* ── Minimal Win32 type re-declarations (no windows.h) ────────────────── */
typedef void*    HANDLE;
typedef u64      SOCKET;
typedef i32      INT;
typedef u32      DWORD;
typedef u16      WORD;
typedef u16      ADDRESS_FAMILY;

#define INVALID_SOCKET_WIN ((SOCKET)(~0ULL))
#define SOCKET_ERROR_WIN   (-1)
#define AF_INET_WIN        2
#define SOCK_STREAM_WIN    1
#define IPPROTO_TCP_WIN    6
#define SOL_SOCKET_WIN     0xffff
#define SO_REUSEADDR_WIN   4
#define FIONBIO_WIN        0x8004667eUL

/* Winsock ABI — we link ws2_32.dll, but via GetProcAddress in phase 2 */
extern __declspec(dllimport) SOCKET __stdcall socket(INT, INT, INT);
extern __declspec(dllimport) INT    __stdcall bind(SOCKET, const void*, INT);
extern __declspec(dllimport) INT    __stdcall listen(SOCKET, INT);
extern __declspec(dllimport) SOCKET __stdcall accept(SOCKET, void*, INT*);
extern __declspec(dllimport) INT    __stdcall recv(SOCKET, void*, INT, INT);
extern __declspec(dllimport) INT    __stdcall send(SOCKET, const void*, INT, INT);
extern __declspec(dllimport) INT    __stdcall closesocket(SOCKET);
extern __declspec(dllimport) INT    __stdcall ioctlsocket(SOCKET, DWORD, u32*);
extern __declspec(dllimport) INT    __stdcall WSAStartup(WORD, void*);

/* ── WSAStartup once on first socket create ───────────────────────────── */
static i32 g_wsa_init = 0;

static void ensure_wsa(void) {
    if (g_wsa_init) return;
    /* WSAData is 408 bytes on 64-bit — we don't inspect it */
    u8 wsadata[408];
    WSAStartup(0x0202 /* version 2.2 */, wsadata);
    g_wsa_init = 1;
}

/* ── Platform API implementation ──────────────────────────────────────── */
vision_socket_t vision_socket_create(i32 af, i32 type, i32 proto) {
    ensure_wsa();
    SOCKET s = socket(af, type, proto);
    return (s == INVALID_SOCKET_WIN) ? VISION_INVALID_SOCKET : (vision_socket_t)s;
}

i32 vision_socket_bind(vision_socket_t s, const void* addr, u32 addrlen) {
    return bind((SOCKET)s, addr, (INT)addrlen);
}

i32 vision_socket_listen(vision_socket_t s, i32 backlog) {
    return listen((SOCKET)s, backlog);
}

vision_socket_t vision_socket_accept(vision_socket_t s, void* addr, u32* addrlen) {
    SOCKET c = accept((SOCKET)s, addr, (INT*)addrlen);
    return (c == INVALID_SOCKET_WIN) ? VISION_INVALID_SOCKET : (vision_socket_t)c;
}

isize vision_socket_read(vision_socket_t s, void* buf, usize len) {
    return (isize)recv((SOCKET)s, (void*)buf, (INT)len, 0);
}

isize vision_socket_write(vision_socket_t s, const void* buf, usize len) {
    return (isize)send((SOCKET)s, (const void*)buf, (INT)len, 0);
}

i32 vision_socket_close(vision_socket_t s) {
    return closesocket((SOCKET)s);
}

i32 vision_socket_setnonblock(vision_socket_t s) {
    u32 mode = 1;
    return ioctlsocket((SOCKET)s, FIONBIO_WIN, &mode);
}

void vision_exit(i32 code) {
    /* NtTerminateProcess — we call it via inline asm on x64 */
    /* syscall nr for NtTerminateProcess is 0x2C on typical Win10/11 */
    /* Phase 2 will use our MASM stub — for now use the intrinsic */
    __debugbreak(); /* placeholder: replace with NT syscall stub */
    (void)code;
}
