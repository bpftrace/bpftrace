if(NOT EMBED_CLANG)
  return()
endif()
include(embed_helpers)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(EMBEDDED_BUILD_TYPE "RelWithDebInfo")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(EMBEDDED_BUILD_TYPE "MinSizeRel")
else()
  set(EMBEDDED_BUILD_TYPE ${CMAKE_BUILD_TYPE})
endif()

if(${EMBEDDED_LLVM_VERSION} VERSION_GREATER_EQUAL "12")
  set(LLVM_FULL_VERSION "12.0.0")
  set(CLANG_DOWNLOAD_URL "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_FULL_VERSION}-rc3/clang-${LLVM_FULL_VERSION}rc3.src.tar.xz")
  set(CLANG_URL_CHECKSUM "SHA256=1267b88d4590d638bab598cc5b54ba0b7520c9aa35d931206941b66f90e7e2f5")
else()
  message(FATAL_ERROR "No supported LLVM version has been specified with LLVM_VERSION (LLVM_VERSION=${EMBEDDED_LLVM_VERSION}), aborting")
endif()

ProcessorCount(nproc)
set(LIBCLANG_INSTALL_COMMAND
    "mkdir -p <INSTALL_DIR>/lib/ && \
     cp <BINARY_DIR>/lib/libclang.a <INSTALL_DIR>/lib/libclang.a"
    )

set(CLANG_INSTALL_COMMAND INSTALL_COMMAND /bin/bash -c
    "${CMAKE_MAKE_PROGRAM} install -j${nproc} && ${LIBCLANG_INSTALL_COMMAND}"
   )

if(NOT EMBED_LLVM)
  # If not linking and building against embedded LLVM, patches may need to
  # be applied to link with the distribution LLVM. This is handled by a
  # helper function
  prepare_clang_patches(patch_command)
  set(CLANG_PATCH_COMMAND PATCH_COMMAND /bin/bash -c "${patch_command}")
endif()

if(EMBED_LIBCLANG_ONLY)
  set(CLANG_LIBRARY_TARGETS clang)
  set(CLANG_BUILD_COMMAND BUILD_COMMAND /bin/bash -c
      "${CMAKE_MAKE_PROGRAM} libclang_static -j${nproc}"
     )
  set(CLANG_INSTALL_COMMAND INSTALL_COMMAND /bin/bash -c "${LIBCLANG_INSTALL_COMMAND}")

  # Include system clang here to deal with the rest of the targets
  find_package(Clang REQUIRED)
  include_directories(SYSTEM ${CLANG_INCLUDE_DIRS})
else()
  set(CLANG_LIBRARY_TARGETS
      clang
      clangAST
      clangAnalysis
      clangBasic
      clangDriver
      clangEdit
      clangFormat
      clangFrontend
      clangIndex
      clangLex
      clangParse
      clangRewrite
      clangSema
      clangSerialization
      clangToolingCore
      clangToolingInclusions
      )
endif()

# These configure flags are a blending of the Alpine, debian, and gentoo
# packages configure flags, customized to reduce build targets as much as
# possible
set(CLANG_CONFIGURE_FLAGS
    -Wno-dev
    -DLLVM_TARGETS_TO_BUILD=BPF
    -DCMAKE_BUILD_TYPE=${EMBEDDED_BUILD_TYPE}
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DCMAKE_VERBOSE_MAKEFILE=OFF
    -DCLANG_VENDOR=bpftrace
    -DCLANG_BUILD_EXAMPLES=OFF
    -DCLANG_INCLUDE_DOCS=OFF
    -DCLANG_INCLUDE_TESTS=OFF
    -DCLANG_PLUGIN_SUPPORT=ON
    -DLIBCLANG_BUILD_STATIC=ON
    -DLLVM_ENABLE_EH=ON
    -DLLVM_ENABLE_RTTI=ON
    -DCLANG_BUILD_TOOLS=OFF
   )

# If LLVM is being embedded, inform Clang to use its Cmake file instead of system
if(EMBED_LLVM)
  list(APPEND CLANG_CONFIGURE_FLAGS  -DLLVM_DIR=${EMBEDDED_LLVM_INSTALL_DIR}/lib/cmake/llvm)
endif()

set(CLANG_TARGET_LIBS "")
foreach(clang_target IN LISTS CLANG_LIBRARY_TARGETS)
  list(APPEND CLANG_TARGET_LIBS "<INSTALL_DIR>/lib/lib${clang_target}.a")
endforeach(clang_target)

ExternalProject_Add(embedded_clang
   URL "${CLANG_DOWNLOAD_URL}"
   URL_HASH "${CLANG_URL_CHECKSUM}"
   CMAKE_ARGS "${CLANG_CONFIGURE_FLAGS}"
   ${CLANG_PATCH_COMMAND}
   ${CLANG_BUILD_COMMAND}
   ${CLANG_INSTALL_COMMAND}
   BUILD_BYPRODUCTS ${CLANG_TARGET_LIBS}
   UPDATE_DISCONNECTED 1
   DOWNLOAD_NO_PROGRESS 1
 )

# If LLVM is also being embedded, build it first
if (EMBED_LLVM)
  ExternalProject_Add_StepDependencies(embedded_clang install embedded_llvm)
endif()

# Set up library targets and locations
ExternalProject_Get_Property(embedded_clang INSTALL_DIR)
set(EMBEDDED_CLANG_INSTALL_DIR ${INSTALL_DIR})
set(CLANG_EMBEDDED_CMAKE_TARGETS "")

include_directories(SYSTEM ${EMBEDDED_CLANG_INSTALL_DIR}/include)

foreach(clang_target IN LISTS CLANG_LIBRARY_TARGETS)
  # Special handling is needed to not overlap with the library definition from
  # system cmake files for Clang's "clang" target.
  if(EMBED_LIBCLANG_ONLY AND ${clang_target} STREQUAL "clang")
    set(clang_target "embedded-libclang")
    list(APPEND CLANG_EMBEDDED_CMAKE_TARGETS ${clang_target})
    add_library(${clang_target} STATIC IMPORTED)
    set_property(TARGET ${clang_target} PROPERTY IMPORTED_LOCATION ${EMBEDDED_CLANG_INSTALL_DIR}/lib/libclang.a)
    add_dependencies(${clang_target} embedded_clang)
  else()
    list(APPEND CLANG_EMBEDDED_CMAKE_TARGETS ${clang_target})
    add_library(${clang_target} STATIC IMPORTED)
    set_property(TARGET ${clang_target} PROPERTY IMPORTED_LOCATION ${EMBEDDED_CLANG_INSTALL_DIR}/lib/lib${clang_target}.a)
    add_dependencies(${clang_target} embedded_clang)
  endif()
endforeach(clang_target)
