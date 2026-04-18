target_sources(vision_core PRIVATE
    router.c
)

target_include_directories(vision_core PRIVATE
    "${CMAKE_SOURCE_DIR}/src/router"
    "${CMAKE_SOURCE_DIR}/src/http"
)
