target_sources(vision_core PRIVATE
    handshake.c
    record.c
)

target_include_directories(vision_core PRIVATE
    "${CMAKE_SOURCE_DIR}/src/tls"
    "${CMAKE_SOURCE_DIR}/src/crypto"
)
