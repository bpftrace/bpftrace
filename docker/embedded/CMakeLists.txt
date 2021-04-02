cmake_minimum_required(VERSION 3.16)
project(bpftrace-llvm-builder)

include(GNUInstallDirs)

set(STATIC_LINKING ON CACHE BOOL "Build bpftrace as a statically linked executable")
set(STATIC_LIBC OFF CACHE BOOL "Attempt to embed libc, only known to work with musl. Has issues with dlopen.")
set(EMBED_LLVM ON CACHE BOOL "Build LLVM static libs as an ExternalProject and link to these instead of system libs.")
set(EMBED_CLANG ON CACHE BOOL "Build Clang static libs as an ExternalProject and link to these instead of system libs.")
set(EMBED_LIBCLANG_ONLY OFF CACHE BOOL "Build only libclang.a, and link to system libraries statically")
set(LLVM_VERSION "12" CACHE STRING "Embedded LLVM/Clang version to build and link against.")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed)
include(embed_helpers)

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(CMAKE_LINK_SEARCH_START_STATIC TRUE)
set(CMAKE_LINK_SEARCH_END_STATIC TRUE)

set(FIND_LIBRARY_USE_LIB64_PATHS TRUE)

cmake_policy(SET CMP0075 NEW)

include(embed_llvm)
include(embed_clang)
