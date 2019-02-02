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

option(USE_BUNDLED "Use bundled dependencies." ON)
option(USE_BUNDLED_BCC "Use the bundled version of bcc." ${USE_BUNDLED})
option(USE_BUNDLED_GTEST "Use the bundled version of gtest." ${USE_BUNDLED})
option(OFFLINE_BUILDS "Don't try to update external dependencies." OFF)
if (OFFLINE_BUILDS)
  set_property(DIRECTORY PROPERTY EP_UPDATE_DISCONNECTED 1)
endif()

enable_testing()

if (USE_BUNDLED_BCC)
include(ExternalProject)
ExternalProject_Add(bcc
  GIT_REPOSITORY https://github.com/iovisor/bcc
  STEP_TARGETS build update
  EXCLUDE_FROM_ALL 1
  BUILD_COMMAND ${CMAKE_COMMAND} --build . --target bcc-static
  )
endif()

function(LinkBCC name)
  if (USE_BUNDLED_BCC)
    ExternalProject_Get_Property(bcc source_dir binary_dir)
    target_include_directories(${name} PUBLIC ${source_dir}/src/cc)
    target_link_libraries(${name} ${binary_dir}/src/cc/libbpf.a)
    target_link_libraries(${name} ${binary_dir}/src/cc/libbcc-loader-static.a)
    target_link_libraries(${name} ${binary_dir}/src/cc/libbcc.a)
    target_link_libraries(${name} ${binary_dir}/src/cc/frontends/clang/libclang_frontend.a)
  else()
    find_path(BCC_INCLUDE_DIR
      NAMES "bcc_elf.h"
      PATH_SUFFIXES "bcc")
    find_library(BCC_LIBRARY NAMES bcc libbcc)
    if (NOT BCC_INCLUDE_DIR OR NOT BCC_LIBRARY)
      message(FATAL_ERROR "bcc library required, but not found!")
    endif()
    target_include_directories(${name} PUBLIC ${BCC_INCLUDE_DIR})
    target_link_libraries(${name} ${BCC_LIBRARY})
  endif()
  target_link_libraries(${name} ${LIBELF_LIBRARIES})
endfunction(LinkBCC)

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
