add_library(vision_platform STATIC
    syscall.S     # AT&T syntax, macOS BSD syscall ABI
    socket.c
    kqueue.c
    mem_ops.c
)

target_include_directories(vision_platform PUBLIC
    "${CMAKE_SOURCE_DIR}/include"
)
