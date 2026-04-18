/*
 * platform/*/mem_ops.c
 * C fallback implementations of vision_memset / vision_memcpy / vision_memcmp
 * for platforms where the ASM version is not compiled in (Windows, or
 * if the ASM stubs are disabled).
 *
 * On Linux and macOS the ASM stubs in syscall.asm / syscall.S provide
 * these symbols. On Windows we fall back to this file.
 * The CMakeLists for each platform decides which translation units to include.
 */
#include "vision/platform.h"

#if defined(VISION_OS_WIN32)
/* Windows: ASM stubs don't export vision_memset etc., so we define them here */

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

/* Windows vision_exit via TerminateProcess */
void vision_exit(i32 code) {
    typedef void (__stdcall *PfnExitProcess)(u32);
    extern void* __stdcall GetProcAddress(void*, const char*);
    extern void* __stdcall GetModuleHandleA(const char*);
    void* k = GetModuleHandleA("kernel32");
    PfnExitProcess fn = (PfnExitProcess)GetProcAddress(k, "ExitProcess");
    if (fn) fn((u32)code);
    /* If resolution failed, spin — can't do much without stdlib */
    for(;;) {}
}

#elif defined(VISION_OS_MACOS)
/*
 * macOS: ASM in syscall.S provides vision_memset/memcpy/memcmp/exit.
 * This file intentionally empty for macOS to avoid duplicate symbols.
 */
#elif defined(VISION_OS_LINUX)
/*
 * Linux: ASM in syscall.asm provides everything.
 * This file intentionally empty for Linux.
 */
#endif
