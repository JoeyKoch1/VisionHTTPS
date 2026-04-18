#include "vision/platform.h"

#if defined(VISION_OS_WIN32)

void* vision_memset(void* dst, i32 val, usize n) {
    u8* p = (u8*)dst;
    u8  v = (u8)val;
    for (usize i = 0; i < n; i++) p[i] = v;
    return dst;
}

void* vision_memcpy(void* dst, const void* src, usize n) {
    u8*       d = (u8*)dst;
    const u8* s = (const u8*)src;
    for (usize i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

i32 vision_memcmp(const void* a, const void* b, usize n) {
    const u8* pa = (const u8*)a;
    const u8* pb = (const u8*)b;
    for (usize i = 0; i < n; i++) {
        if (pa[i] != pb[i]) return (i32)pa[i] - (i32)pb[i];
    }
    return 0;
}

void vision_exit(i32 code) {
    typedef void (__stdcall *PfnExitProcess)(u32);
    extern void* __stdcall GetProcAddress(void*, const char*);
    extern void* __stdcall GetModuleHandleA(const char*);
    void* k = GetModuleHandleA("kernel32");
    PfnExitProcess fn = (PfnExitProcess)GetProcAddress(k, "ExitProcess");
    if (fn) fn((u32)code);
    for(;;) {}
}

#elif defined(VISION_OS_MACOS)
#elif defined(VISION_OS_LINUX)
#endif
