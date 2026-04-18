target_sources(vision_core PRIVATE
    parser.c
    response.c
)

target_include_directories(vision_core PRIVATE
    "${CMAKE_SOURCE_DIR}/src/http"
)
