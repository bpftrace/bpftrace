cmake_minimum_required(VERSION 2.8.12)
project(bpftrace)

set(STATIC_LINKING OFF CACHE BOOL "Build bpftrace as a statically linked executable")

add_compile_options("-std=c++14")
add_compile_options("-Wno-format-security")
#add_compile_options("-Wall")
#add_compile_options("-Wextra")
#add_compile_options("-Wundef")
#add_compile_options("-Wpointer-arith")
#add_compile_options("-Wcast-align")
#add_compile_options("-Wwrite-strings")
#add_compile_options("-Wcast-qual")
#add_compile_options("-Wswitch-default")
#add_compile_options("-Wswitch-enum")
#add_compile_options("-Wconversion")
#add_compile_options("-Wunreachable-code")
#add_compile_options("-Wformat=2")
#add_compile_options("-Wstrict-overflow=5")
#add_compile_options("-Wdisabled-optimization")

enable_testing()

if (OFFLINE_BUILDS)
  include(ExternalProject)
  ExternalProject_Add(bcc
    GIT_REPOSITORY https://github.com/iovisor/bcc
    STEP_TARGETS build update
    EXCLUDE_FROM_ALL 1
    UPDATE_DISCONNECTED 1
    BUILD_COMMAND ${CMAKE_COMMAND} --build . --target bcc-static
    )
else()
  include(ExternalProject)
  ExternalProject_Add(bcc
    GIT_REPOSITORY https://github.com/iovisor/bcc
    STEP_TARGETS build update
    EXCLUDE_FROM_ALL 1
    BUILD_COMMAND ${CMAKE_COMMAND} --build . --target bcc-static
    )
endif()

if (STATIC_LINKING)
  set(CMAKE_EXE_LINKER_FLAGS "-static")
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(CMAKE_LINK_SEARCH_START_STATIC TRUE)
  set(CMAKE_LINK_SEARCH_END_STATIC TRUE)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(LibElf REQUIRED)
include_directories(${LIBELF_INCLUDE_DIRS})

find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)
bison_target(bison_parser src/parser.yy ${CMAKE_BINARY_DIR}/parser.tab.cc)
flex_target(flex_lexer src/lexer.l ${CMAKE_BINARY_DIR}/lex.yy.cc)
add_flex_bison_dependency(flex_lexer bison_parser)
add_library(parser ${BISON_bison_parser_OUTPUTS} ${FLEX_flex_lexer_OUTPUTS})
target_include_directories(parser PUBLIC src src/ast ${CMAKE_BINARY_DIR})

include(CheckSymbolExists)
set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(name_to_handle_at "sys/types.h;sys/stat.h;fcntl.h" HAVE_NAME_TO_HANDLE_AT)
set(CMAKE_REQUIRED_DEFINITIONS)

find_package(LLVM REQUIRED)
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

find_package(Clang REQUIRED)
include_directories(${CLANG_INCLUDE_DIRS})

add_subdirectory(src/arch)
add_subdirectory(src/ast)
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(resources)
add_subdirectory(tools)
add_subdirectory(man)
