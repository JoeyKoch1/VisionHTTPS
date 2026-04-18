if(MSVC)
    add_compile_options(
        /W4         # high warning level
        /WX         # warnings as errors
        /GS-        # disable buffer security checks (we roll our own)
        /Gs999999   # disable stack probes
        /nodefaultlib  # no CRT linkage
        /Oi         # enable intrinsics
        /O2         # optimize
    )
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX)

elseif(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(
        -Wall -Wextra -Werror
        -fno-builtin          # no implicit libc builtins
        -fno-stack-protector  # we handle our own stack hardening
        -fomit-frame-pointer
        -O2
        -march=native         # use host CPU features (AES-NI, AVX2 etc.)
    )

    if(VISION_PLATFORM STREQUAL "linux")
        # Prevent the linker pulling in glibc unless we explicitly say so
        add_link_options(-nostdlib -static)
    elseif(VISION_PLATFORM STREQUAL "macos")
        # macOS needs the system library for syscall ABI — no full libc though
        add_link_options(-nostdlib)
    endif()
endif()

# ASM source files — enable assembler language globally
enable_language(ASM)
if(MSVC)
    # MASM for Windows
    enable_language(ASM_MASM)
endif()
