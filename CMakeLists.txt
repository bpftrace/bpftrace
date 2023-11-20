cmake_minimum_required(VERSION 3.13.0)
project(bpftrace)

cmake_policy(SET CMP0057 NEW)

# bpftrace version number components.
set(bpftrace_VERSION_MAJOR 0)
set(bpftrace_VERSION_MINOR 19)
set(bpftrace_VERSION_PATCH 0)

include(GNUInstallDirs)

set(WARNINGS_AS_ERRORS OFF CACHE BOOL "Build with -Werror")
set(STATIC_LINKING OFF CACHE BOOL "Build bpftrace as a statically linked executable")

set(BUILD_ASAN OFF CACHE BOOL "Build bpftrace with -fsanitize=address")
set(ENABLE_MAN ON CACHE BOOL "Build man pages")
set(BUILD_TESTING ON CACHE BOOL "Build test suite")
set(ENABLE_TEST_VALIDATE_CODEGEN ON CACHE BOOL "Run LLVM IR validation tests")
set(VENDOR_GTEST OFF CACHE BOOL "Clone gtest from github")
set(BUILD_FUZZ OFF CACHE BOOL "Build bpftrace for fuzzing")
set(USE_LIBFUZZER OFF CACHE BOOL "Use libfuzzer for fuzzing")
set(FUZZ_TARGET "codegen" CACHE STRING "Fuzzing target")

set(ENABLE_SKB_OUTPUT ON CACHE BOOL "Enable skb_output, will include libpcap")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

add_compile_options("-Wall")
add_compile_options("-Wextra")
add_compile_options("-Wundef")
add_compile_options("-Wpointer-arith")
add_compile_options("-Wcast-align")
add_compile_options("-Wwrite-strings")
add_compile_options("-Wcast-qual")
#add_compile_options("-Wconversion")
add_compile_options("-Wunreachable-code")
#add_compile_options("-Wformat=2")
add_compile_options("-Wdisabled-optimization")

if (WARNINGS_AS_ERRORS)
  add_compile_options("-Werror")
endif()

# Clang compiler produces narrowing errors when calling BPF_LD_MAP_FD in the bcc library
# Turning off them before bcc library fixes this
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  add_compile_options("-Wno-narrowing")
endif()

# Ninja buffers output so gcc/clang think it's not an interactive session.
# Colors are useful for compiler errors so force the color
if("${CMAKE_GENERATOR}" STREQUAL "Ninja")
  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    add_compile_options(-fdiagnostics-color=always)
  elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    add_compile_options(-fcolor-diagnostics)
  endif()
endif()

include(CTest)

if(STATIC_LINKING)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(CMAKE_LINK_SEARCH_START_STATIC TRUE)
  set(CMAKE_LINK_SEARCH_END_STATIC TRUE)
endif(STATIC_LINKING)

set_property( GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS TRUE )

include_directories(SYSTEM ${KERNEL_INCLUDE_DIRS})

find_package(ZLIB REQUIRED)
include_directories(SYSTEM ${ZLIB_INCLUDE_DIRS})

find_package(LibBcc REQUIRED)
include_directories(SYSTEM ${LIBBCC_INCLUDE_DIRS})

find_package(LibBpf REQUIRED)
include_directories(SYSTEM ${LIBBPF_INCLUDE_DIRS})

find_package(LibElf REQUIRED)
include_directories(SYSTEM ${LIBELF_INCLUDE_DIRS})

find_package(LibCereal REQUIRED)
include_directories(SYSTEM ${LIBCEREAL_INCLUDE_DIRS})

find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)
# `parser_class_name` is deprecated and generates warnings in bison >= 3.3.
# But `api.parser.class` is not supported in bison < 3.3. So we must inject
# the %define based on the bison version here.
if(${BISON_VERSION} VERSION_GREATER_EQUAL 3.3)
  set(BISON_FLAGS "-Dapi.parser.class={Parser}")
else()
  set(BISON_FLAGS "-Dparser_class_name={Parser}")
endif()
bison_target(bison_parser src/parser.yy ${CMAKE_BINARY_DIR}/parser.tab.cc COMPILE_FLAGS ${BISON_FLAGS} VERBOSE)
flex_target(flex_lexer src/lexer.l ${CMAKE_BINARY_DIR}/lex.yy.cc)
add_flex_bison_dependency(flex_lexer bison_parser)
add_library(parser ${BISON_bison_parser_OUTPUTS} ${FLEX_flex_lexer_OUTPUTS})
target_compile_options(parser PRIVATE "-w")
target_include_directories(parser PUBLIC src src/ast ${CMAKE_BINARY_DIR})

include(CheckSymbolExists)
set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(name_to_handle_at "sys/types.h;sys/stat.h;fcntl.h" HAVE_NAME_TO_HANDLE_AT)
set(CMAKE_REQUIRED_DEFINITIONS)

find_package(LibBfd)
find_package(LibOpcodes)
find_package(LibDw)

if(ENABLE_SKB_OUTPUT)
find_package(LibPcap)
endif()

if(POLICY CMP0075)
  cmake_policy(SET CMP0075 NEW)
endif()

if(${LIBBFD_FOUND} AND ${LIBOPCODES_FOUND})
  set(HAVE_BFD_DISASM TRUE)
endif()

include(CheckIncludeFile)
check_include_file("sys/sdt.h" HAVE_SYSTEMTAP_SYS_SDT_H)

# Some users have multiple versions of llvm installed and would like to specify
# a specific llvm version.
if(${LLVM_REQUESTED_VERSION})
  find_package(LLVM ${LLVM_REQUESTED_VERSION} REQUIRED)
else()
  find_package(LLVM REQUIRED)
endif()

set(MIN_LLVM_MAJOR 6)
set(MAX_LLVM_MAJOR 17)

if((${LLVM_VERSION_MAJOR} VERSION_LESS ${MIN_LLVM_MAJOR}) OR (${LLVM_VERSION_MAJOR} VERSION_GREATER ${MAX_LLVM_MAJOR}))
  message(SEND_ERROR "Unsupported LLVM version found via ${LLVM_INCLUDE_DIRS}: ${LLVM_VERSION_MAJOR}")
  message(SEND_ERROR "Only versions between ${MIN_LLVM_MAJOR} and ${MAX_LLVM_MAJOR} are supported")
  message(SEND_ERROR "Specify an LLVM major version using LLVM_REQUESTED_VERSION=<major version>")
endif()

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}: ${LLVM_CMAKE_DIR}")
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_definitions(-DLLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR})
add_definitions(-DLLVM_VERSION_MINOR=${LLVM_VERSION_MINOR})
add_definitions(-DLLVM_VERSION_PATCH=${LLVM_VERSION_PATCH})

find_package(Clang REQUIRED)
include_directories(SYSTEM ${CLANG_INCLUDE_DIRS})

# BPFtrace compile definitions

set(BPFTRACE_FLAGS)
if (ALLOW_UNSAFE_PROBE)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_UNSAFE_PROBE)
endif(ALLOW_UNSAFE_PROBE)

if(HAVE_NAME_TO_HANDLE_AT)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_NAME_TO_HANDLE_AT=1)
endif(HAVE_NAME_TO_HANDLE_AT)

if(HAVE_BFD_DISASM)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_BFD_DISASM)
  if(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
    set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  endif(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  if(LIBBFD_INIT_DISASM_INFO_FOUR_ARGS_SIGNATURE)
    set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" LIBBFD_INIT_DISASM_INFO_FOUR_ARGS_SIGNATURE)
  endif(LIBBFD_INIT_DISASM_INFO_FOUR_ARGS_SIGNATURE)
endif(HAVE_BFD_DISASM)

if (LIBDW_FOUND)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBDW)
endif ()

if(LIBPCAP_FOUND)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBPCAP)
endif(LIBPCAP_FOUND)

if (HAVE_LIBBPF_UPROBE_MULTI)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBBPF_UPROBE_MULTI)
endif(HAVE_LIBBPF_UPROBE_MULTI)

add_subdirectory(src)
if (BUILD_TESTING)
  add_subdirectory(tests)
endif()
add_subdirectory(tools)
if (ENABLE_MAN)
  add_subdirectory(man)
endif(ENABLE_MAN)

if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CmakeUninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/CmakeUninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
	  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/CmakeUninstall.cmake)
endif()
