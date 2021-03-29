cmake_minimum_required(VERSION 3.8)
project(bpftrace)

# bpftrace version number components.
include(GNUInstallDirs)

set(LLVM_VERSION "8" CACHE STRING "Embedded LLVM/Clang version to build and link against.")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/../cmake /bpftrace/cmake/)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/embed /bpftrace/cmake/embed)
include(embed_helpers)

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

set(FIND_LIBRARY_USE_LIB64_PATHS TRUE)

include_directories(SYSTEM ${KERNEL_INCLUDE_DIRS})

if(POLICY CMP0075)
  cmake_policy(SET CMP0075 NEW)
endif()

include(embed_llvm)
include(embed_clang)
