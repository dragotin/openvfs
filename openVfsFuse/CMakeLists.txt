cmake_minimum_required(VERSION 3.16)

project(openVfsFuse LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_compile_definitions(_FILE_OFFSET_BITS=64)
add_compile_definitions(FUSE_USE_VERSION=30)
add_compile_definitions(HAVE_SETXATTR)

find_package(fuse REQUIRED)
add_subdirectory(src)
