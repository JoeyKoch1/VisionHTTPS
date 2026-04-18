add_library(vision_core STATIC)

add_subdirectory(mem)
add_subdirectory(net)
add_subdirectory(crypto)
add_subdirectory(tls)
add_subdirectory(http)
add_subdirectory(router)
add_subdirectory(arch/${VISION_ARCH})

target_sources(vision_core PRIVATE config.c)

target_include_directories(vision_core PUBLIC
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/src"
    "${CMAKE_SOURCE_DIR}/src/crypto"
    "${CMAKE_SOURCE_DIR}/src/mem"
    "${CMAKE_SOURCE_DIR}/src/net"
    "${CMAKE_SOURCE_DIR}/src/tls"
    "${CMAKE_SOURCE_DIR}/src/http"
    "${CMAKE_SOURCE_DIR}/src/router"
)

target_link_libraries(vision_core PUBLIC vision_platform)

add_executable(vision_server main.c)
target_link_libraries(vision_server PRIVATE vision_core)

if(VISION_OS_WIN32)
    set_target_properties(vision_server PROPERTIES
        LINK_FLAGS "/ENTRY:vision_winmain"
    )
elseif(VISION_OS_LINUX OR VISION_OS_MACOS)
    set_target_properties(vision_server PROPERTIES
        LINK_FLAGS "-nostdlib"
    )
endif()
