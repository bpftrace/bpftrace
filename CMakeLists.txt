cmake_minimum_required(VERSION 3.14)
project(bpftrace)

# bpftrace version number components.
set(bpftrace_VERSION_MAJOR 0)
set(bpftrace_VERSION_MINOR 24)
set(bpftrace_VERSION_PATCH 0)

# project settings.
set(STATIC_LINKING OFF CACHE BOOL "Build bpftrace as a statically linked executable")
set(BUILD_ASAN OFF CACHE BOOL "Build bpftrace with -fsanitize=address")
set(BUILD_UBSAN OFF CACHE BOOL "Build bpftrace with -fsanitize=undefined")
set(ENABLE_MAN ON CACHE BOOL "Build man pages")
set(BUILD_TESTING ON CACHE BOOL "Build test suite")
set(ENABLE_SYSTEMD OFF CACHE BOOL "Enable systemd integration")
set(KERNEL_HEADERS_DIR "" CACHE PATH "Hard-code kernel headers directory")
set(SYSTEM_INCLUDE_PATHS "auto" CACHE STRING "Hard-code system include paths (colon separated, the default value \"auto\" queries clang at runtime)")
set(WARNINGS_AS_ERRORS OFF CACHE BOOL "Build with -Werror")
set(HARDENED_STDLIB OFF CACHE BOOL "Enable hardened definitions for standard library (for development use only)")
set(ENABLE_SKB_OUTPUT ON CACHE BOOL "Enable skb_output, will include libpcap")
set(USE_SYSTEM_LIBBPF OFF CACHE BOOL
    "Use system libbpf instead of vendoring it from a submodule")

# cmake settings & builtin modules.
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0075 NEW)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS TRUE)
if(STATIC_LINKING)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(CMAKE_LINK_SEARCH_START_STATIC TRUE)
  set(CMAKE_LINK_SEARCH_END_STATIC TRUE)
endif(STATIC_LINKING)

include(GNUInstallDirs)
include(CTest)
include(CheckSymbolExists)
include(CheckIncludeFile)

# Ninja buffers output so gcc/clang think it's not an interactive session.
# Colors are useful for compiler errors so force the color
if("${CMAKE_GENERATOR}" STREQUAL "Ninja")
  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    add_compile_options(-fdiagnostics-color=always)
  elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    add_compile_options(-fcolor-diagnostics)
  endif()
endif()

# compilation settings; all warnings are universally enabled and set as errors.
# The additional enabled warnings are those not necessarily covered by `-Wextra`
# and `-Wall`, and are generally desirable. In the future `-Wconversion` may be
# enabled, but there are a large number of implicit conversions to be removed.
add_compile_options("-Wall")
add_compile_options("-Wextra")
add_compile_options("-Wundef")
add_compile_options("-Wnarrowing")
add_compile_options("-Wpointer-arith")
add_compile_options("-Wcast-align")
add_compile_options("-Wcast-qual")
add_compile_options("-Wwrite-strings")
add_compile_options("-Werror")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  # Including the standard C++ <algorithms> header will always produce a false
  # positive warning for certain versions when -O3 is specified [1]. In order
  # to avoid this, just disable this check for release mode. The check will
  # still apply for non-release modes, so we still have sufficient coverage.
  # [1] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=101361
  add_compile_options("-Wno-stringop-overread")
  # Similarly, it seems that std::function is a bit broken with the g++
  # uninitialized values and -O3. The same logic allows us to disable this
  # check here, since it will be caught well by other builds.
  add_compile_options("-Wno-uninitialized")
endif()


# Note: these can be replaced in the future by the `CMAKE_INCLUDE_CURRENT_DIR`
# setting, but this requires additional workarounds for the current `resources`
# library and the way that it is built.
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_BINARY_DIR})


# Dependency declarations. In the future, these can be moved next to the actual
# dependencies that need them, and the scope of the includes narrowed.
find_package(ZLIB REQUIRED)
include_directories(SYSTEM ${ZLIB_INCLUDE_DIRS})

find_package(LibBcc REQUIRED)
include_directories(SYSTEM ${LIBBCC_INCLUDE_DIRS})

find_package(LibBpf REQUIRED)
include_directories(SYSTEM ${LIBBPF_INCLUDE_DIRS})
if(USE_SYSTEM_LIBBPF)
  message(WARNING "Using system libbpf, please ensure that the version is greater than or equal to the submodule")
endif()

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
  set(BISON_FLAGS "-Dapi.parser.class={Parser} -Wcounterexamples")
else()
  set(BISON_FLAGS "-Dparser_class_name={Parser} -Wcounterexamples")
endif()
bison_target(bison_parser src/parser.yy ${CMAKE_BINARY_DIR}/parser.tab.cc COMPILE_FLAGS ${BISON_FLAGS} VERBOSE)
flex_target(flex_lexer src/lexer.l ${CMAKE_BINARY_DIR}/lex.yy.cc)
add_flex_bison_dependency(flex_lexer bison_parser)
add_library(parser STATIC ${BISON_bison_parser_OUTPUTS} ${FLEX_flex_lexer_OUTPUTS})
target_compile_options(parser PRIVATE "-w")
target_include_directories(parser PRIVATE src src/ast)

find_package(LibBfd)
find_package(LibOpcodes)
find_package(LibDw)

if(ENABLE_SKB_OUTPUT)
  find_package(LibPcap)
endif()

if(ENABLE_SYSTEMD)
  find_package(PkgConfig)
  pkg_check_modules(libsystemd REQUIRED IMPORTED_TARGET libsystemd)
endif()

find_package(LibBlazesym)

if(LIBBLAZESYM_FOUND)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_BLAZESYM)
  include_directories(SYSTEM ${LIBBLAZESYM_INCLUDE_DIRS})
endif()

# Some users have multiple versions of llvm installed and would like to specify
# a specific llvm version.
if(${LLVM_REQUESTED_VERSION})
  find_package(LLVM ${LLVM_REQUESTED_VERSION} REQUIRED)
else()
  find_package(LLVM REQUIRED)
endif()

set(MIN_LLVM_MAJOR 17)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  # We assume bpftrace is not being packaged when CMAKE_BUILD_TYPE=Debug.
  # So allow building with any LLVM version. This is purely for developers.
  # Packagers are highly discouraged from shipping bpftrace with untested LLVM
  # releases.
  set(MAX_LLVM_MAJOR 999)
else()
  set(MAX_LLVM_MAJOR 21)
endif()

if((${LLVM_VERSION_MAJOR} VERSION_LESS ${MIN_LLVM_MAJOR}) OR (${LLVM_VERSION_MAJOR} VERSION_GREATER ${MAX_LLVM_MAJOR}))
  message(SEND_ERROR "Unsupported LLVM version found via ${LLVM_INCLUDE_DIRS}: ${LLVM_VERSION_MAJOR}")
  message(SEND_ERROR "Only versions between ${MIN_LLVM_MAJOR} and ${MAX_LLVM_MAJOR} are supported")
  message(SEND_ERROR "Specify an LLVM major version using LLVM_REQUESTED_VERSION=<major version>")
endif()

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}: ${LLVM_CMAKE_DIR}")
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

string(REGEX REPLACE "-rc[0-9]+" "" CLANG_VERSION ${LLVM_PACKAGE_VERSION})

find_package(Clang ${CLANG_VERSION} REQUIRED)
include_directories(SYSTEM ${CLANG_INCLUDE_DIRS})


# Definitions for availability of different libraries and APIs. These are
# currently packaged into a single `BPFTRACE_FLAGS` variable which can be
# consumed, but this may be pushed lower if packages and include paths (above)
# can also be pushed next to dependencies.
set(BPFTRACE_FLAGS)

set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(name_to_handle_at "sys/types.h;sys/stat.h;fcntl.h" HAVE_NAME_TO_HANDLE_AT)
set(CMAKE_REQUIRED_DEFINITIONS)
if(HAVE_NAME_TO_HANDLE_AT)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_NAME_TO_HANDLE_AT=1)
endif(HAVE_NAME_TO_HANDLE_AT)

# HAVE_BFD_DISASM is used elsewhere, as well as directly here.
if(${LIBBFD_FOUND} AND ${LIBOPCODES_FOUND})
  set(HAVE_BFD_DISASM TRUE)
endif()
if(HAVE_BFD_DISASM)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_BFD_DISASM)
  if(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
    set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  endif(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  if(LIBBFD_INIT_DISASM_INFO_FOUR_ARGS_SIGNATURE)
    set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" LIBBFD_INIT_DISASM_INFO_FOUR_ARGS_SIGNATURE)
  endif(LIBBFD_INIT_DISASM_INFO_FOUR_ARGS_SIGNATURE)
endif(HAVE_BFD_DISASM)

if(LIBDW_FOUND)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBDW)
endif()

if(LIBPCAP_FOUND)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBPCAP)
endif(LIBPCAP_FOUND)

if(ENABLE_SYSTEMD)
  set(BPFTRACE_FLAGS "${BPFTRACE_FLAGS}" HAVE_LIBSYSTEMD)
endif()

# This definition is used by some tests to set flags when generating code, but
# is not broadly incoprorated into `BPFTRACE_FLAGS`.
check_include_file("sys/sdt.h" HAVE_SYSTEMTAP_SYS_SDT_H)

# Subdirectories.
add_subdirectory(src)
if (BUILD_TESTING)
  add_subdirectory(tests)
endif()
add_subdirectory(tools)
if (ENABLE_MAN)
  add_subdirectory(man)
endif(ENABLE_MAN)


# Miscellaneous install rules and a generic uninstall rule.
set(BASH_COMPLETION_PATH ${CMAKE_CURRENT_SOURCE_DIR}/scripts/bash-completion/bpftrace)
install(FILES ${BASH_COMPLETION_PATH} DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/bash-completion/completions)

if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CmakeUninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/CmakeUninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
	  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/CmakeUninstall.cmake)
endif()
