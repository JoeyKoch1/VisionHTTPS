# cmake/platform_detect.cmake
# Detects OS + arch and sets VISION_PLATFORM, VISION_ARCH

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(VISION_PLATFORM "linux")
    add_compile_definitions(VISION_OS_LINUX=1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(VISION_PLATFORM "win32")
    add_compile_definitions(VISION_OS_WIN32=1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(VISION_PLATFORM "macos")
    add_compile_definitions(VISION_OS_MACOS=1)
else()
    message(FATAL_ERROR "[Vision] Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

# ── Architecture ────────────────────────────────────────────────────────────
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    set(VISION_ARCH "x86_64")
    add_compile_definitions(VISION_ARCH_X86_64=1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(VISION_ARCH "arm64")
    add_compile_definitions(VISION_ARCH_ARM64=1)
else()
    message(FATAL_ERROR "[Vision] Unsupported arch: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

message(STATUS "[Vision] Platform : ${VISION_PLATFORM}")
message(STATUS "[Vision] Arch     : ${VISION_ARCH}")
