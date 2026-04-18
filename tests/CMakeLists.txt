add_executable(vision_tests
    test_sha256.c
    test_aes_gcm.c
    test_chacha20.c
    test_mem.c
    test_http.c
    test_x25519.c
    test_runner.c
)

target_link_libraries(vision_tests PRIVATE vision_core)
target_include_directories(vision_tests PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/src"
    "${CMAKE_SOURCE_DIR}/src/crypto"
    "${CMAKE_SOURCE_DIR}/src/mem"
    "${CMAKE_SOURCE_DIR}/src/http"
    "${CMAKE_SOURCE_DIR}/src/tls"
    "${CMAKE_SOURCE_DIR}/src/router"
)
