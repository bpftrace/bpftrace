cmake_minimum_required(VERSION 2.8.12)
project(bpftrace)

# bpftrace version number components.
set(bpftrace_VERSION_MAJOR 0)
set(bpftrace_VERSION_MINOR 9)

set(STATIC_LINKING OFF CACHE BOOL "Build bpftrace as a statically linked executable")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

add_compile_options("-std=c++14")
add_compile_options("-Wno-format-security")
add_compile_options("-Wall")
add_compile_options("-Wextra")
add_compile_options("-Wundef")
add_compile_options("-Wpointer-arith")
add_compile_options("-Wcast-align")
add_compile_options("-Wwrite-strings")
add_compile_options("-Wcast-qual")
add_compile_options("-Wswitch-default")
#add_compile_options("-Wswitch-enum")
#add_compile_options("-Wconversion")
add_compile_options("-Wunreachable-code")
#add_compile_options("-Wformat=2")
add_compile_options("-Wstrict-overflow=5")
add_compile_options("-Wdisabled-optimization")

include(CTest)

if (STATIC_LINKING)
  set(CMAKE_EXE_LINKER_FLAGS "-static")
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(CMAKE_LINK_SEARCH_START_STATIC TRUE)
  set(CMAKE_LINK_SEARCH_END_STATIC TRUE)
endif()

set(FIND_LIBRARY_USE_LIB64_PATHS TRUE)

find_package(LibBcc REQUIRED)
include_directories(SYSTEM ${LIBBCC_INCLUDE_DIRS})

find_package(LibElf REQUIRED)
include_directories(SYSTEM ${LIBELF_INCLUDE_DIRS})

find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)
bison_target(bison_parser src/parser.yy ${CMAKE_BINARY_DIR}/parser.tab.cc VERBOSE)
flex_target(flex_lexer src/lexer.l ${CMAKE_BINARY_DIR}/lex.yy.cc)
add_flex_bison_dependency(flex_lexer bison_parser)
add_library(parser ${BISON_bison_parser_OUTPUTS} ${FLEX_flex_lexer_OUTPUTS})
target_compile_options(parser PRIVATE "-w")
target_include_directories(parser PUBLIC src src/ast ${CMAKE_BINARY_DIR})

include(CheckSymbolExists)
set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(name_to_handle_at "sys/types.h;sys/stat.h;fcntl.h" HAVE_NAME_TO_HANDLE_AT)
set(CMAKE_REQUIRED_DEFINITIONS)

if(POLICY CMP0075)
  cmake_policy(SET CMP0075 NEW)
endif()
set(CMAKE_REQUIRED_LIBRARIES bcc)
check_symbol_exists(bcc_prog_load "${LIBBCC_INCLUDE_DIRS}/libbpf.h" HAVE_BCC_PROG_LOAD)
check_symbol_exists(bcc_create_map "${LIBBCC_INCLUDE_DIRS}/libbpf.h" HAVE_BCC_CREATE_MAP)
check_symbol_exists(bcc_elf_foreach_sym "${LIBBCC_INCLUDE_DIRS}/bcc_elf.h" HAVE_BCC_ELF_FOREACH_SYM)

include(CheckTypeSize)
set(CMAKE_EXTRA_INCLUDE_FILES linux/bpf.h)
# This will set HAVE_GET_CURRENT_CGROUP_ID to TRUE or FALSE
check_type_size("BPF_FUNC_get_current_cgroup_id" GET_CURRENT_CGROUP_ID LANGUAGE C)
set(CMAKE_EXTRA_INCLUDE_FILES)

# Some users have multiple versions of llvm installed and would like to specify
# a specific llvm version.
if(${LLVM_REQUESTED_VERION})
  find_package(LLVM ${LLVM_REQUESTED_VERION} REQUIRED)
else()
  find_package(LLVM REQUIRED)
endif()

if(${LLVM_VERSION_MAJOR} VERSION_LESS 5)
  message(SEND_ERROR "Unsupported LLVM version found: ${LLVM_INCLUDE_DIRS}")
  message(SEND_ERROR "Specify an LLVM major version using LLVM_REQUESTED_VERSION=<major version>")
endif()

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

find_package(Clang REQUIRED)
include_directories(SYSTEM ${CLANG_INCLUDE_DIRS})

add_subdirectory(src/arch)
add_subdirectory(src/ast)
add_subdirectory(src)
if (BUILD_TESTING)
	add_subdirectory(tests)
endif()
add_subdirectory(resources)
add_subdirectory(tools)
add_subdirectory(man)
