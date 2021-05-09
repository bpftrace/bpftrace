if(NOT EMBED_USE_LLVM)
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

if(${LLVM_VERSION} VERSION_EQUAL "12.0.0")
  set(CLANG_DOWNLOAD_URL "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/clang-${LLVM_VERSION}.src.tar.xz")
  set(CLANG_URL_CHECKSUM "SHA256=e26e452e91d4542da3ebbf404f024d3e1cbf103f4cd110c26bf0a19621cca9ed")
elseif(${LLVM_VERSION} VERSION_EQUAL "8.0.1")
  set(CLANG_DOWNLOAD_URL "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/cfe-${LLVM_VERSION}.src.tar.xz")
  set(CLANG_URL_CHECKSUM "SHA256=70effd69f7a8ab249f66b0a68aba8b08af52aa2ab710dfb8a0fba102685b1646")
else()
  message(FATAL_ERROR "No supported LLVM version has been specified with LLVM_VERSION (${EMBED_LLVM_VERSION}), aborting")
endif()

ProcessorCount(nproc)
set(LIBCLANG_INSTALL_COMMAND
    "mkdir -p <INSTALL_DIR>/lib/ && \
     cp <BINARY_DIR>/lib/libclang.a <INSTALL_DIR>/lib/libclang.a"
    )

set(CLANG_INSTALL_COMMAND INSTALL_COMMAND /bin/bash -c
    "${CMAKE_MAKE_PROGRAM} install -j${nproc} && ${LIBCLANG_INSTALL_COMMAND}"
   )

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

if(${EMBED_LLVM_VERSION} VERSION_EQUAL "12")
  set(CLANG_LIBRARY_TARGETS ${CLANG_LIBRARY_TARGETS}
      clangAPINotes # 12
      clangARCMigrate
      clangASTMatchers
      clangCodeGen
      clangCrossTU
      clangDependencyScanning #12
      clangDirectoryWatcher #12
      clangDynamicASTMatchers
      clangFrontendTool
      clangHandleCXX
      clangHandleLLVM
      clangIndexSerialization # 12
      clangRewriteFrontend
      clangStaticAnalyzerCheckers
      clangStaticAnalyzerCore
      clangStaticAnalyzerFrontend
      clangTesting
      clangTooling
      clangToolingASTDiff
      clangToolingRefactoring
      clangToolingSyntax
      clangTransformer
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
    -DLLVM_DIR=${EMBEDDED_LLVM_INSTALL_DIR}/lib/cmake/llvm
    )


if(EMBED_BUILD_LLVM)
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

  ExternalProject_Add_StepDependencies(embedded_clang install embedded_llvm)

  # Set up library targets and locations
  ExternalProject_Get_Property(embedded_clang INSTALL_DIR)
  set(EMBEDDED_CLANG_INSTALL_DIR "${INSTALL_DIR}/lib")
else()
  set(EMBEDDED_CLANG_INSTALL_DIR "${EMBED_LLVM_PATH}")
endif(EMBED_BUILD_LLVM)

set(CLANG_EMBEDDED_CMAKE_TARGETS "")
set(CLANG_EMBEDDED_CMAKE_LIBS "")

include_directories(SYSTEM ${EMBEDDED_CLANG_INSTALL_DIR}/include)

foreach(clang_target IN LISTS CLANG_LIBRARY_TARGETS)
  # Special handling is needed to not overlap with the library definition from
  # system cmake files for Clang's "clang" target.
  list(APPEND CLANG_EMBEDDED_CMAKE_TARGETS ${clang_target})
  add_library(${clang_target} STATIC IMPORTED)
  set_property(
    TARGET ${clang_target}
    PROPERTY
      IMPORTED_LOCATION "${EMBEDDED_CLANG_INSTALL_DIR}/lib${clang_target}.a"
  )
  if(EMBED_BUILD_LLVM)
    add_dependencies(${clang_target} embedded_clang)
  endif(EMBED_BUILD_LLVM)
endforeach(clang_target)
