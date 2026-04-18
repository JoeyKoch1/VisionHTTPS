/*
 * tests/test_runner.c
 * Zero-dependency test runner — no test framework, no externs.
 */
#include "vision/platform.h"

#if defined(VISION_OS_LINUX)
extern i64 vision_syscall3(i64, i64, i64, i64);
static void _write(const char* s, usize n) { vision_syscall3(1, 1, (i64)s, (i64)n); }
#elif defined(VISION_OS_MACOS)
extern i64 vision_syscall3(i64, i64, i64, i64);
static void _write(const char* s, usize n) { vision_syscall3(0x2000004, 1, (i64)s, (i64)n); }
#elif defined(VISION_OS_WIN32)
static void _write(const char* s, usize n) { (void)s; (void)n; }
#endif

static usize slen(const char* s) { usize n=0; while(s[n]) n++; return n; }
static void println(const char* s) { _write(s, slen(s)); _write("\n", 1); }

int test_sha256(void);
int test_aes_gcm(void);
int test_chacha20(void);
int test_mem(void);
int test_http(void);
int test_x25519(void);

typedef struct { const char* name; int (*fn)(void); } TestEntry;
static const TestEntry tests[] = {
    { "sha256",    test_sha256  },
    { "aes_gcm",   test_aes_gcm },
    { "chacha20",  test_chacha20},
    { "mem",       test_mem     },
    { "http",      test_http    },
    { "x25519",    test_x25519  },
};

#if defined(VISION_OS_LINUX) || defined(VISION_OS_MACOS)
void _start(void) {
#elif defined(VISION_OS_WIN32)
void __stdcall vision_winmain(void) {
#endif
    i32 failed = 0;
    i32 total  = (i32)(sizeof(tests)/sizeof(tests[0]));
    println("[Vision HTTPS] test suite");
    println("─────────────────────────");
    for (i32 i = 0; i < total; i++) {
        int r = tests[i].fn();
        _write(r == 0 ? "  PASS  " : "  FAIL  ", 8);
        println(tests[i].name);
        if (r != 0) failed++;
    }
    println("─────────────────────────");
    println(failed == 0 ? "ALL PASSED" : "SOME FAILED");
    vision_exit(failed > 0 ? 1 : 0);
}
