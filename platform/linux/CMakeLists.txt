add_library(vision_platform STATIC
    syscall.asm          # raw Linux syscall stubs — x86-64 only for now
    socket.c
    mem_ops.c
)

target_include_directories(vision_platform PUBLIC
    "${CMAKE_SOURCE_DIR}/include"
)
