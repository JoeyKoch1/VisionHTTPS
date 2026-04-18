target_sources(vision_core PRIVATE
    aesni.asm          # AES-NI accelerated AES-GCM  (Linux/macOS: NASM .asm)
    # aesni.asm is also used on Windows via CMake ASM_NASM or MASM variant
    cpuid.c            # CPUID feature detection — confirm AES-NI at runtime
)
