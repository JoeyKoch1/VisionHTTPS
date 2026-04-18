add_library(vision_platform STATIC
    syscall.asm        # MASM — NtCreateFile / NtDeviceIoControlFile stubs
    socket.c           # Winsock2 via NT sockets (no WS2_32 import lib)
    iocp.c             # IOCP event loop
    mem_ops.c
)

target_include_directories(vision_platform PUBLIC
    "${CMAKE_SOURCE_DIR}/include"
)
target_link_libraries(vision_platform PRIVATE ws2_32 ntdll)
