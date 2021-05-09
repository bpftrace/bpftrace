if(NOT EMBED_USE_LLVM)
  return()
endif()
include(embed_helpers)

# TO DO
# Set up cross-compilation
# https://cmake.org/cmake/help/v3.6/manual/cmake-toolchains.7.html#cross-compiling-using-clang
get_host_triple(CHOST)
get_target_triple(CBUILD)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  # Same as debian, see
  # https://salsa.debian.org/pkg-llvm-team/llvm-toolchain/blob/8/debian/rules
  set(EMBEDDED_BUILD_TYPE "RelWithDebInfo")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(EMBEDDED_BUILD_TYPE "MinSizeRel")
else()
  set(EMBEDDED_BUILD_TYPE ${CMAKE_BUILD_TYPE})
endif()

if(${EMBED_LLVM_VERSION} VERSION_EQUAL "12")
  set(LLVM_FULL_VERSION "12.0.0")
  set(LLVM_VERSION ${LLVM_FULL_VERSION})
  set(LLVM_VERSION_MAJOR "12")
  set(LLVM_VERSION_MINOR "0")
  set(LLVM_VERSION_PATCH "0")
  set(LLVM_URL_CHECKSUM "SHA256=49dc47c8697a1a0abd4ee51629a696d7bfe803662f2a7252a3b16fc75f3a8b50")
elseif(${EMBED_LLVM_VERSION} VERSION_EQUAL "8")
  set(LLVM_FULL_VERSION "8.0.1")
  set(LLVM_VERSION ${LLVM_FULL_VERSION})
  set(LLVM_VERSION_MAJOR "8")
  set(LLVM_VERSION_MINOR "0")
  set(LLVM_VERSION_PATCH "1")
  set(LLVM_URL_CHECKSUM "SHA256=44787a6d02f7140f145e2250d56c9f849334e11f9ae379827510ed72f12b75e7")
else()
  message(FATAL_ERROR "No supported LLVM version has been specified with LLVM_VERSION (${EMBED_LLVM_VERSION}), aborting")
endif()

set(LLVM_DOWNLOAD_URL "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_FULL_VERSION}/llvm-${LLVM_FULL_VERSION}.src.tar.xz")

# Default to building almost all targets, + BPF specific ones
set(LLVM_LIBRARY_TARGETS
    LLVMAggressiveInstCombine
    LLVMAnalysis
    LLVMAsmParser
    LLVMAsmPrinter
    LLVMBinaryFormat
    LLVMBitReader
    LLVMBitWriter
    LLVMBPFAsmParser
    LLVMBPFCodeGen
    LLVMBPFDesc
    LLVMBPFDisassembler
    LLVMBPFInfo
    LLVMCodeGen
    LLVMCore
    LLVMCoroutines
    LLVMCoverage
    LLVMDebugInfoCodeView
    LLVMDebugInfoDWARF
    LLVMDebugInfoMSF
    LLVMDebugInfoPDB
    LLVMDemangle
    LLVMDlltoolDriver
    LLVMExecutionEngine
    LLVMFuzzMutate
    LLVMGlobalISel
    LLVMInstCombine
    LLVMInstrumentation
    LLVMInterpreter
    LLVMipo
    LLVMIRReader
    LLVMLibDriver
    LLVMLineEditor
    LLVMLinker
    LLVMLTO
    LLVMMC
    LLVMMCA
    LLVMMCDisassembler
    LLVMMCJIT
    LLVMMCParser
    LLVMMIRParser
    LLVMObjCARCOpts
    LLVMObject
    LLVMObjectYAML
    LLVMOption
    LLVMOrcJIT
    LLVMPasses
    LLVMProfileData
    LLVMRuntimeDyld
    LLVMScalarOpts
    LLVMSelectionDAG
    LLVMSymbolize
    LLVMTableGen
    LLVMTarget
    LLVMTextAPI
    LLVMTransformUtils
    LLVMVectorize
    LLVMWindowsManifest
    LLVMXRay
    LLVMSupport
    )


if(${EMBED_LLVM_VERSION} VERSION_EQUAL "8")
  set(LLVM_LIBRARY_TARGETS ${LLVM_LIBRARY_TARGETS}
      LLVMBPFAsmPrinter
      LLVMOptRemarks
      )
endif()

if(${EMBED_LLVM_VERSION} VERSION_EQUAL "12")
  set(LLVM_LIBRARY_TARGETS ${LLVM_LIBRARY_TARGETS}
    LLVMBitstreamReader
    LLVMCFGuard
    LLVMDWARFLinker
    LLVMDebugInfoGSYM
    LLVMExtensions
    LLVMFileCheck
    LLVMFrontendOpenACC
    LLVMFrontendOpenMP
    LLVMHelloNew
    LLVMInterfaceStub
    LLVMJITLink
    LLVMOrcShared
    LLVMOrcTargetProcess
    LLVMRemarks
    )
endif()

# These build flags are based off of Alpine, Debian and Gentoo packages
# optimized for compatibility and reducing build targets
set(LLVM_CONFIGURE_FLAGS
    -Wno-dev
    -DLLVM_TARGETS_TO_BUILD=BPF
    -DCMAKE_BUILD_TYPE=${EMBEDDED_BUILD_TYPE}
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DLLVM_BINUTILS_INCDIR=/usr/include
    -DLLVM_BUILD_DOCS=OFF
    -DLLVM_BUILD_EXAMPLES=OFF
    -DLLVM_BUILD_EXTERNAL_COMPILER_RT=ON
    -DLLVM_BUILD_LLVM_DYLIB=ON
    -DLLVM_BUILD_TESTS=OFF
    -DLLVM_DEFAULT_TARGET_TRIPLE=${CBUILD}
    -DLLVM_ENABLE_ASSERTIONS=OFF
    -DLLVM_ENABLE_CXX1Y=ON
    -DLLVM_ENABLE_FFI=OFF
    -DLLVM_ENABLE_LIBEDIT=OFF
    -DLLVM_ENABLE_LIBCXX=OFF
    -DLLVM_ENABLE_PIC=ON
    -DLLVM_ENABLE_LIBPFM=OFF
    -DLLVM_ENABLE_EH=ON
    -DLLVM_ENABLE_RTTI=ON
    -DLLVM_ENABLE_SPHINX=OFF
    -DLLVM_ENABLE_TERMINFO=OFF
    -DLLVM_ENABLE_ZLIB=ON
    -DLLVM_HOST_TRIPLE=${CHOST}
    -DLLVM_INCLUDE_EXAMPLES=OFF
    -DLLVM_LINK_LLVM_DYLIB=ON
    -DLLVM_APPEND_VC_REV=OFF
    )


if(EMBED_BUILD_LLVM)
  set(LLVM_TARGET_LIBS "")
  foreach(llvm_target IN LISTS LLVM_LIBRARY_TARGETS)
    list(APPEND LLVM_TARGET_LIBS "<INSTALL_DIR>/lib/lib${llvm_target}.a")
  endforeach(llvm_target)

  ExternalProject_Add(embedded_llvm
    URL "${LLVM_DOWNLOAD_URL}"
    URL_HASH "${LLVM_URL_CHECKSUM}"
    CMAKE_ARGS "${LLVM_CONFIGURE_FLAGS}"
    BUILD_BYPRODUCTS ${LLVM_TARGET_LIBS}
    UPDATE_DISCONNECTED 1
    DOWNLOAD_NO_PROGRESS 1
  )

  # Set up build targets and map to embedded paths
  ExternalProject_Get_Property(embedded_llvm INSTALL_DIR)
  set(EMBEDDED_LLVM_INSTALL_DIR "${INSTALL_DIR}/lib")
else()
  set(EMBEDDED_LLVM_INSTALL_DIR "${EMBED_LLVM_PATH}")
endif()


set(LLVM_EMBEDDED_CMAKE_TARGETS "")

include_directories(SYSTEM ${EMBEDDED_LLVM_INSTALL_DIR}/include)

foreach(llvm_target IN LISTS LLVM_LIBRARY_TARGETS)
  list(APPEND LLVM_EMBEDDED_CMAKE_TARGETS ${llvm_target})
  add_library(${llvm_target} STATIC IMPORTED)
  set_property(
    TARGET ${llvm_target}
    PROPERTY
      IMPORTED_LOCATION "${EMBEDDED_LLVM_INSTALL_DIR}/lib${llvm_target}.a"
  )
  if(EMBED_BUILD_LLVM)
    add_dependencies(${llvm_target} embedded_llvm)
  endif()
endforeach(llvm_target)
