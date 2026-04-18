cmake_minimum_required(VERSION 3.22)
project(VisionHTTPS VERSION 0.1.0 LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD   11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(platform_detect)
include(compiler_flags)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")

add_subdirectory(platform/${VISION_PLATFORM})
add_subdirectory(src)
add_subdirectory(tests)
