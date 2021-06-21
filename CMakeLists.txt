cmake_minimum_required(VERSION 3.13.0)
project(bpftrace)

# bpftrace version number components.
set(bpftrace_VERSION_MAJOR 0)
set(bpftrace_VERSION_MINOR 13)
set(bpftrace_VERSION_PATCH 0)

include(GNUInstallDirs)

set(WARNINGS_AS_ERRORS OFF CACHE BOOL "Build with -Werror")
set(STATIC_LINKING OFF CACHE BOOL "Build bpftrace as a statically linked executable")
set(STATIC_LIBC OFF CACHE BOOL "Attempt to embed libc, only known to work with musl. Has issues with dlopen.")

set(EMBED_USE_LLVM OFF CACHE BOOL "Use a prebuilt embedded LLVM, speeds up the build process")
set(EMBED_BUILD_LLVM OFF CACHE BOOL "Build Clang&LLVM static libs as an ExternalProject and link to these instead of system libs.")
set(EMBED_LLVM_VERSION "8" CACHE STRING "Embedded LLVM/Clang version to build and link against.")

set(BUILD_ASAN OFF CACHE BOOL "Build bpftrace with -fsanitize=address")
set(ENABLE_MAN ON CACHE BOOL "Build man pages")
set(BUILD_TESTING ON CACHE BOOL "Build test suite")
set(ENABLE_TEST_VALIDATE_CODEGEN ON CACHE BOOL "Run LLVM IR validation tests")
set(VENDOR_GTEST OFF CACHE BOOL "Clone gtest from github")
set(BUILD_FUZZ OFF CACHE BOOL "Build bpftrace for fuzzing")
set(USE_LIBFUZZER OFF CACHE BOOL "Use libfuzzer for fuzzing")
set(FUZZ_TARGET "codegen" CACHE STRING "Fuzzing target")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

if(EMBED_BUILD_LLVM)
  set(EMBED_USE_LLVM ON)
endif()

if(EMBED_USE_LLVM AND NOT EMBED_BUILD_LLVM)
  set(EMBED_LLVM_PATH "/usr/local/lib")
endif()

if(EMBED_USE_LLVM OR STATIC_LIBC)
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed)
  include(embed_helpers)
  if (NOT STATIC_LINKING)
    set(CONFIG_ERROR "Dependencies can only be embedded for a static build.\n"
                     "Enable STATIC_LINKING=ON to embed static libs.")
    message(FATAL_ERROR ${CONFIG_ERROR})
  elseif(STATIC_LIBC)
    message(WARNING "static libc is known to cause problems, consider STATIC_LIBC=OFF. Proceed at your own risk") #iovisor/bpftrace/issues/266
  endif()
endif()

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

find_package(LibBcc REQUIRED)
include_directories(SYSTEM ${LIBBCC_INCLUDE_DIRS})

find_package(LibElf REQUIRED)
include_directories(SYSTEM ${LIBELF_INCLUDE_DIRS})

find_package(LibCereal REQUIRED)
include_directories(SYSTEM ${CEREAL_INCLUDE_DIRS})

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

find_package(LibBpf)
find_package(LibBfd)
find_package(LibOpcodes)

if(POLICY CMP0075)
  cmake_policy(SET CMP0075 NEW)
endif()
if(STATIC_LINKING)
  set(CMAKE_REQUIRED_LIBRARIES bcc bcc_bpf bpf elf z)
else()
  set(CMAKE_REQUIRED_LIBRARIES ${LIBBCC_LIBRARIES})
  if (LIBBPF_FOUND)
      set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} ${LIBBPF_LIBRARIES})
  endif()
endif(STATIC_LINKING)
get_filename_component(LIBBCC_LIBDIR ${LIBBCC_LIBRARIES} DIRECTORY)
set(CMAKE_REQUIRED_LINK_OPTIONS -L${LIBBCC_LIBDIR})

check_symbol_exists(bcc_prog_load "${LIBBCC_INCLUDE_DIRS}/bcc/libbpf.h" HAVE_BCC_PROG_LOAD)
check_symbol_exists(bcc_create_map "${LIBBCC_INCLUDE_DIRS}/bcc/libbpf.h" HAVE_BCC_CREATE_MAP)
check_symbol_exists(bcc_elf_foreach_sym "${LIBBCC_INCLUDE_DIRS}/bcc/bcc_elf.h" HAVE_BCC_ELF_FOREACH_SYM)
check_symbol_exists(bpf_attach_kfunc "${LIBBCC_INCLUDE_DIRS}/bcc/libbpf.h" HAVE_BCC_KFUNC)
check_symbol_exists(bcc_usdt_addsem_probe "${LIBBCC_INCLUDE_DIRS}/bcc/bcc_usdt.h" HAVE_BCC_USDT_ADDSEM)

# bcc_prog_load_xattr needs struct bpf_load_program_attr,
# which is defined in libbpf
if (LIBBPF_FOUND)
  check_symbol_exists(bcc_prog_load_xattr "${LIBBCC_INCLUDE_DIRS}/bcc/libbpf.h" HAVE_BCC_PROG_LOAD_XATTR)
endif()
set(CMAKE_REQUIRED_LIBRARIES)
set(CMAKE_REQUIRED_LINK_OPTIONS)

if(${LIBBFD_FOUND} AND ${LIBOPCODES_FOUND})
  set(HAVE_BFD_DISASM TRUE)
endif()

include(CheckIncludeFile)
check_include_file("sys/sdt.h" HAVE_SYSTEMTAP_SYS_SDT_H)

if (EMBED_USE_LLVM)
  include(embed_llvm)
else()
  # Some users have multiple versions of llvm installed and would like to specify
  # a specific llvm version.
  if(${LLVM_REQUESTED_VERSION})
    find_package(LLVM ${LLVM_REQUESTED_VERSION} REQUIRED)
  else()
    find_package(LLVM REQUIRED)
  endif()

  if((${LLVM_VERSION_MAJOR} VERSION_LESS 6) OR (${LLVM_VERSION_MAJOR} VERSION_GREATER 12))
    message(SEND_ERROR "Unsupported LLVM version found: ${LLVM_INCLUDE_DIRS}")
    message(SEND_ERROR "Specify an LLVM major version using LLVM_REQUESTED_VERSION=<major version>")
  endif()

  message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}: ${LLVM_CMAKE_DIR}")
  include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
  add_definitions(${LLVM_DEFINITIONS})
endif()

add_definitions(-DLLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR})
add_definitions(-DLLVM_VERSION_MINOR=${LLVM_VERSION_MINOR})
add_definitions(-DLLVM_VERSION_PATCH=${LLVM_VERSION_PATCH})

if(${LLVM_VERSION_MAJOR} VERSION_GREATER_EQUAL 11)
  set(LLVM_ORC_V2)
  add_definitions(-DLLVM_ORC_V2)
  message(STATUS "Using LLVM orcv2")
else()
  add_definitions(-DLLVM_ORC_V1)
endif()

if(EMBED_USE_LLVM)
  include(embed_clang)
else()
  find_package(Clang REQUIRED)
  include_directories(SYSTEM ${CLANG_INCLUDE_DIRS})
endif()

# BPFtrace compile definitions

set(BPFTRACE_FLAGS)
if (ALLOW_UNSAFE_PROBE)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_UNSAFE_PROBE)
endif(ALLOW_UNSAFE_PROBE)

if(HAVE_NAME_TO_HANDLE_AT)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_NAME_TO_HANDLE_AT=1)
endif(HAVE_NAME_TO_HANDLE_AT)

if(HAVE_BCC_PROG_LOAD)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_BCC_PROG_LOAD)
endif(HAVE_BCC_PROG_LOAD)

if(HAVE_BCC_CREATE_MAP)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_BCC_CREATE_MAP)
endif(HAVE_BCC_CREATE_MAP)

if(HAVE_BCC_ELF_FOREACH_SYM)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_BCC_ELF_FOREACH_SYM)
endif(HAVE_BCC_ELF_FOREACH_SYM)

if(HAVE_BCC_USDT_ADDSEM)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_BCC_USDT_ADDSEM)
endif(HAVE_BCC_USDT_ADDSEM)

if(LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
endif(LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)

if(LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
endif(LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)

if (HAVE_BCC_KFUNC)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_BCC_KFUNC)
endif(HAVE_BCC_KFUNC)

if (HAVE_LIBBPF_LINK_CREATE OR HAVE_BCC_PROG_LOAD_XATTR)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBBPF_BPF_H)
endif()

if (LIBBPF_FOUND)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBBPF)
endif(LIBBPF_FOUND)

if (HAVE_LIBBPF_MAP_BATCH)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBBPF_MAP_BATCH)
endif()

if (HAVE_LIBBPF_LINK_CREATE)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBBPF_LINK_CREATE)
endif()

if (HAVE_BCC_PROG_LOAD_XATTR)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_BCC_PROG_LOAD_XATTR)
endif()

if(HAVE_BFD_DISASM)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_BFD_DISASM)
  if(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
    set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  endif(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
endif(HAVE_BFD_DISASM)

if (LIBBPF_BTF_DUMP_FOUND)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBBPF_BTF_DUMP)
  if (HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
    set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
  endif()
endif(LIBBPF_BTF_DUMP_FOUND)

add_subdirectory(src/arch)
add_subdirectory(src/ast)
add_subdirectory(src)
if (BUILD_TESTING)
  add_subdirectory(tests)
endif()
add_subdirectory(resources)
add_subdirectory(tools)
if (ENABLE_MAN)
add_subdirectory(man)
endif(ENABLE_MAN)
