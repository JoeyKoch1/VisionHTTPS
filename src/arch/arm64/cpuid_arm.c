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
    {
        #define SYS___sysctl 202
        
        typedef struct {
            u32 namelen;
            u32* name;
            u32 oldlen;
            void* oldval;
            u32 newlen;
            void* newval;
        } SysctlArgs;
        
        extern i64 vision_syscall6(i64 nr, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6);
        
        u32 feat_aes_name[] = { 1, 6, 15, 1 };
        u32 feat_pmull_name[] = { 1, 6, 15, 2 };
        u32 feat_sha_name[] = { 1, 6, 15, 3 };
        
        i64 val;
        u32 len = sizeof(val);
        SysctlArgs args;
        
        args.namelen = 4;
        args.name = feat_aes_name;
        args.oldlen = len;
        args.oldval = &val;
        args.newlen = 0;
        args.newval = VISION_NULL;
        if (vision_syscall6(0x2000000 | SYS___sysctl, (i64)&args, 0, 0, 0, 0, 0) == 0 && val == 1) {
            g_hwcap |= HWCAP_AES;
        }
        
        args.namelen = 4;
        args.name = feat_pmull_name;
        args.oldlen = len;
        args.oldval = &val;
        args.newlen = 0;
        args.newval = VISION_NULL;
        if (vision_syscall6(0x2000000 | SYS___sysctl, (i64)&args, 0, 0, 0, 0, 0) == 0 && val == 1) {
            g_hwcap |= HWCAP_PMULL;
        }
        
        args.namelen = 4;
        args.name = feat_sha_name;
        args.oldlen = len;
        args.oldval = &val;
        args.newlen = 0;
        args.newval = VISION_NULL;
        if (vision_syscall6(0x2000000 | SYS___sysctl, (i64)&args, 0, 0, 0, 0, 0) == 0 && val == 1) {
            g_hwcap |= HWCAP_SHA2;
        }
    }
#elif defined(VISION_OS_WIN32)
    {
        typedef i32 (__stdcall *PfnIsProcessorFeaturePresent)(u32);
        typedef HANDLE (__stdcall *PfnGetModuleHandleA)(const char*);
        typedef void* (__stdcall *PfnGetProcAddress)(HANDLE, const char*);
        
        extern HANDLE __stdcall GetModuleHandleA(const char*);
        extern void* __stdcall GetProcAddress(HANDLE, const char*);
        
        #define PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE 30
        #define PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE 31
        
        HANDLE hKernel = GetModuleHandleA("kernel32.dll");
        if (hKernel) {
            PfnIsProcessorFeaturePresent pIsProcFeat = (PfnIsProcessorFeaturePresent)
                GetProcAddress(hKernel, "IsProcessorFeaturePresent");
            if (pIsProcFeat) {
                if (pIsProcFeat(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE)) {
                    g_hwcap |= HWCAP_AES;
                    g_hwcap |= HWCAP_PMULL;
                    g_hwcap |= HWCAP_SHA2;
                }
            }
        }
    }
#endif
}

bool8 vision_cpu_has_aesni(void)  { return (g_hwcap & HWCAP_AES)   ? VISION_TRUE : VISION_FALSE; }
bool8 vision_cpu_has_avx2(void)   { return VISION_FALSE; }
bool8 vision_cpu_has_pclmul(void) { return (g_hwcap & HWCAP_PMULL) ? VISION_TRUE : VISION_FALSE; }
bool8 vision_cpu_has_sha(void)    { return (g_hwcap & HWCAP_SHA2)  ? VISION_TRUE : VISION_FALSE; }
