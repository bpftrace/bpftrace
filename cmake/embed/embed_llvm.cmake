if(NOT EMBED_LLVM)
  return()
endif()
include(embed_helpers)

if(${LLVM_VERSION} VERSION_GREATER_EQUAL "9")
  set(LLVM_FULL_VERSION "9.0.1")
  set(LLVM_DOWNLOAD_URL "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_FULL_VERSION}/llvm-${LLVM_FULL_VERSION}.src.tar.xz")
  set(LLVM_URL_CHECKSUM "SHA256=00a1ee1f389f81e9979f3a640a01c431b3021de0d42278f6508391a2f0b81c9a")
elseif(${LLVM_VERSION} VERSION_GREATER_EQUAL "8")
  set(LLVM_FULL_VERSION "8.0.1")
  set(LLVM_DOWNLOAD_URL "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_FULL_VERSION}/llvm-${LLVM_FULL_VERSION}.src.tar.xz")
  set(LLVM_URL_CHECKSUM "SHA256=44787a6d02f7140f145e2250d56c9f849334e11f9ae379827510ed72f12b75e7")
elseif(${LLVM_VERSION} VERSION_GREATER_EQUAL "7")
  set(LLVM_FULL_VERSION "7.1.0")
  set(LLVM_DOWNLOAD_URL "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_FULL_VERSION}/llvm-${LLVM_FULL_VERSION}.src.tar.xz")
  set(LLVM_URL_CHECKSUM "SHA256=1bcc9b285074ded87b88faaedddb88e6b5d6c331dfcfb57d7f3393dd622b3764")
else()
  message(FATAL_ERROR "No supported LLVM version has been specified with LLVM_VERSION (LLVM_VERSION=${LLVM_VERSION}), aborting")
endif()

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
    LLVMBPFAsmPrinter
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
    LLVMOptRemarks
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

get_host_triple(CHOST)
get_target_triple(CBUILD)
# These build flags are based off of Alpine, Debian and Gentoo packages
# optimized for compatibility and reducing build targets
set(LLVM_CONFIGURE_FLAGS
    -Wno-dev
    -DLLVM_TARGETS_TO_BUILD=BPF
    -DCMAKE_BUILD_TYPE=MinSizeRel
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DLLVM_BINUTILS_INCDIR=/usr/include
    -DLLVM_BUILD_DOCS=OFF
    -DLLVM_BUILD_EXAMPLES=OFF
    -DLLVM_INCLUDE_EXAMPLES=OFF
    -DLLVM_BUILD_EXTERNAL_COMPILER_RT=ON
    -DLLVM_BUILD_LLVM_DYLIB=ON
    -DLLVM_LINK_LLVM_DYLIB=OFF
    -DLLVM_BUILD_TESTS=OFF
    -DLLVM_INCLUDE_TESTS=OFF
    -DLLVM_BUILD_TOOLS=OFF
    -DLLVM_INCLUDE_TOOLS=OFF
    -DLLVM_INCLUDE_BENCHMARKS=OFF
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
    -DLLVM_APPEND_VC_REV=OFF
    )


llvm_platform_config(LLVM_PATCH_COMMAND
                    "${LLVM_CONFIGURE_FLAGS}"
                    LLVM_BUILD_COMMAND
                    LLVM_INSTALL_COMMAND)

set(LLVM_TARGET_LIBS "")
foreach(llvm_target IN LISTS LLVM_LIBRARY_TARGETS)
  list(APPEND LLVM_TARGET_LIBS "<INSTALL_DIR>/lib/lib${llvm_target}.a")
endforeach(llvm_target)

ExternalProject_Add(embedded_llvm
  URL "${LLVM_DOWNLOAD_URL}"
  URL_HASH "${LLVM_URL_CHECKSUM}"
  CMAKE_ARGS "${LLVM_CONFIGURE_FLAGS}"
  ${LLVM_BUILD_COMMAND}
  ${LLVM_INSTALL_COMMAND}
  BUILD_BYPRODUCTS ${LLVM_TARGET_LIBS}
  UPDATE_DISCONNECTED 1
  DOWNLOAD_NO_PROGRESS 1
)

# Set up build targets and map to embedded paths
ExternalProject_Get_Property(embedded_llvm INSTALL_DIR)
set(EMBEDDED_LLVM_INSTALL_DIR ${INSTALL_DIR})
set(LLVM_EMBEDDED_CMAKE_TARGETS "")
include_directories(SYSTEM ${EMBEDDED_LLVM_INSTALL_DIR}/include)

foreach(llvm_target IN LISTS LLVM_LIBRARY_TARGETS)
  list(APPEND LLVM_EMBEDDED_CMAKE_TARGETS ${llvm_target})
  add_library(${llvm_target} STATIC IMPORTED)
  set_property(TARGET ${llvm_target} PROPERTY IMPORTED_LOCATION ${EMBEDDED_LLVM_INSTALL_DIR}/lib/lib${llvm_target}.a)
  add_dependencies(${llvm_target} embedded_llvm)
endforeach(llvm_target)
