/*
 * src/arch/x86_64/cpuid.c
 * Runtime CPU feature detection.
 * Uses the CPUID instruction directly via inline asm — no <cpuid.h>.
 */
#include "vision/platform.h"

typedef struct {
    u32 eax, ebx, ecx, edx;
} CpuidResult;

static VISION_INLINE CpuidResult do_cpuid(u32 leaf, u32 subleaf) {
    CpuidResult r;
#if defined(_MSC_VER)
    i32 regs[4];
    __cpuidex(regs, (i32)leaf, (i32)subleaf);
    r.eax = (u32)regs[0]; r.ebx = (u32)regs[1];
    r.ecx = (u32)regs[2]; r.edx = (u32)regs[3];
#else
    __asm__ volatile (
        "cpuid"
        : "=a"(r.eax), "=b"(r.ebx), "=c"(r.ecx), "=d"(r.edx)
        : "a"(leaf), "c"(subleaf)
    );
#endif
    return r;
}

/* Cached flags — filled once at startup */
static u32 g_cpu_flags = 0;

#define CPU_FLAG_AESNI  (1u << 0)
#define CPU_FLAG_AVX2   (1u << 1)
#define CPU_FLAG_PCLMUL (1u << 2)
#define CPU_FLAG_SHA    (1u << 3)

void vision_cpu_detect(void) {
    CpuidResult r1 = do_cpuid(1, 0);
    if (r1.ecx & (1u << 25)) g_cpu_flags |= CPU_FLAG_AESNI;
    if (r1.ecx & (1u << 1))  g_cpu_flags |= CPU_FLAG_PCLMUL;

    CpuidResult r7 = do_cpuid(7, 0);
    if (r7.ebx & (1u << 5))  g_cpu_flags |= CPU_FLAG_AVX2;
    if (r7.ebx & (1u << 29)) g_cpu_flags |= CPU_FLAG_SHA;
}

bool8 vision_cpu_has_aesni(void)  { return (g_cpu_flags & CPU_FLAG_AESNI)  ? VISION_TRUE : VISION_FALSE; }
bool8 vision_cpu_has_avx2(void)   { return (g_cpu_flags & CPU_FLAG_AVX2)   ? VISION_TRUE : VISION_FALSE; }
bool8 vision_cpu_has_pclmul(void) { return (g_cpu_flags & CPU_FLAG_PCLMUL) ? VISION_TRUE : VISION_FALSE; }
bool8 vision_cpu_has_sha(void)    { return (g_cpu_flags & CPU_FLAG_SHA)    ? VISION_TRUE : VISION_FALSE; }
