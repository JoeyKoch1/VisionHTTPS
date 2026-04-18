target_sources(vision_core PRIVATE
    sha256.c
    aes_gcm.c
    chacha20.c
    hmac.c
    x25519.c
)

target_include_directories(vision_core PRIVATE
    "${CMAKE_SOURCE_DIR}/src/crypto"
)
