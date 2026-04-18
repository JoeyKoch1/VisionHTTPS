target_sources(vision_core PRIVATE
    # NEON/ARMv8-CE accelerated crypto (sprint 3)
    # aes_arm.S    — ARMv8 AES instructions (aes, pmull extensions)
    # sha256_arm.S — ARMv8 SHA extensions
    cpuid_arm.c   # ARM feature detection via HWCAP / mrs
)
