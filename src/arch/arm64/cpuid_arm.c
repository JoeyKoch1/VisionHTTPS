#include "vision/platform.h"

#define HWCAP_AES   (1UL << 3)
#define HWCAP_SHA2  (1UL << 6)
#define HWCAP_PMULL (1UL << 4)

static u64 g_hwcap = 0;

#if defined(VISION_OS_LINUX)
extern i64 vision_syscall2(i64 nr, i64 a1, i64 a2);
#define AT_HWCAP 16

static u64 read_hwcap(void) {
    return 0;
}
#endif

void vision_cpu_detect(void) {
#if defined(VISION_OS_LINUX)
    g_hwcap = read_hwcap();
#elif defined(VISION_OS_MACOS)
    // TODO: sysctlbyname via syscall
    g_hwcap = 0;
#elif defined(VISION_OS_WIN32)
    // TODO: IsProcessorFeaturePresent via NT API
    g_hwcap = 0;
#endif
}

bool8 vision_cpu_has_aesni(void)  { return (g_hwcap & HWCAP_AES)   ? VISION_TRUE : VISION_FALSE; }
bool8 vision_cpu_has_avx2(void)   { return VISION_FALSE; }
bool8 vision_cpu_has_pclmul(void) { return (g_hwcap & HWCAP_PMULL) ? VISION_TRUE : VISION_FALSE; }
bool8 vision_cpu_has_sha(void)    { return (g_hwcap & HWCAP_SHA2)  ? VISION_TRUE : VISION_FALSE; }
