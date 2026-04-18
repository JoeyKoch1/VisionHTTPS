/*
 * src/arch/arm64/cpuid_arm.c
 * ARMv8 CPU feature detection.
 *
 * On Linux:  parse /proc/cpuinfo or use auxval (AT_HWCAP / AT_HWCAP2).
 * On macOS:  sysctlbyname("hw.optional.arm.FEAT_AES") etc.
 * On Win:    IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE)
 *
 * We read the system register directly on Linux where permitted,
 * otherwise fall back to auxval.
 */
#include "vision/platform.h"

#define HWCAP_AES   (1UL << 3)
#define HWCAP_SHA2  (1UL << 6)
#define HWCAP_PMULL (1UL << 4)

static u64 g_hwcap = 0;

#if defined(VISION_OS_LINUX)
/* getauxval(AT_HWCAP) via direct syscall — no libc getauxval() */
extern i64 vision_syscall2(i64 nr, i64 a1, i64 a2);
#define AT_HWCAP 16

static u64 read_hwcap(void) {
    /*
     * We read from the auxiliary vector by scanning /proc/self/auxv.
     * The auxv is a sequence of (type, value) u64 pairs.
     * This is the cleanest zero-extern approach.
     *
     * Sprint 3: implement the /proc/self/auxv reader.
     */
    return 0; /* stub — assume no extensions until reader lands */
}
#endif

void vision_cpu_detect(void) {
#if defined(VISION_OS_LINUX)
    g_hwcap = read_hwcap();
#elif defined(VISION_OS_MACOS)
    /* TODO: sysctlbyname via syscall */
    g_hwcap = 0;
#elif defined(VISION_OS_WIN32)
    /* TODO: IsProcessorFeaturePresent via NT API */
    g_hwcap = 0;
#endif
}

bool8 vision_cpu_has_aesni(void)  { return (g_hwcap & HWCAP_AES)   ? VISION_TRUE : VISION_FALSE; }
bool8 vision_cpu_has_avx2(void)   { return VISION_FALSE; }
bool8 vision_cpu_has_pclmul(void) { return (g_hwcap & HWCAP_PMULL) ? VISION_TRUE : VISION_FALSE; }
bool8 vision_cpu_has_sha(void)    { return (g_hwcap & HWCAP_SHA2)  ? VISION_TRUE : VISION_FALSE; }
