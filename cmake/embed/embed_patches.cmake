# Patch function for clang to be able to link to system LLVM
function(prepare_clang_patches patch_command)
  message("Building embedded Clang against host LLVM, checking compatibiilty...")
  detect_host_os(HOST_OS_ID)
  detect_host_os_family(HOST_OS_FAMILY)

  set(CLANG_PATCH_COMMAND "/bin/true")
  if(HOST_OS_ID STREQUAL "debian" OR HOST_OS_ID STREQUAL "ubuntu" OR HOST_OS_FAMILY STREQUAL "debian")
    message("Building on a debian-like system, will apply minimal debian patches to clang sources in order to build.")
    set(PATCH_NAME "debian-patches.tar.gz")
    set(PATCH_PATH "${CMAKE_CURRENT_BINARY_DIR}/debian-llvm/")
    set(DEBIAN_PATCH_SERIES "")
    list(APPEND DEBIAN_PATCH_SERIES "kfreebsd/clang_lib_Basic_Targets.diff -p2")

    if(${LLVM_VERSION} VERSION_EQUAL "8" OR ${LLVM_VERSION} VERSION_GREATER "8" )
      set(DEBIAN_PATCH_URL_BASE "https://salsa.debian.org/pkg-llvm-team/llvm-toolchain/-/archive/debian/")
      set(DEBIAN_PATCH_URL_PATH "8_8.0.1-1/llvm-toolchain-debian-8_8.0.1-1.tar.gz?path=debian%2Fpatches")
      set(DEBIAN_PATCH_URL "${DEBIAN_PATCH_URL_BASE}/${DEBIAN_PATCH_URL_PATH}")
      set(DEBIAN_PATCH_CHECKSUM 2b845a5de3cc2d49924b632d3e7a2fca53c55151e586528750ace2cb2aae23db)
    else()
      message(FATAL_ERROR "No supported LLVM version has been specified with LLVM_VERSION (LLVM_VERSION=${LLVM_VERSION}), aborting")
    endif()

    list(LENGTH DEBIAN_PATCH_SERIES NUM_PATCHES)
    message("${NUM_PATCHES} patches will be applied for Clang ${LLVM_VERSION} on ${HOST_OS_ID}/${HOST_OS_ID_LIKE}")
    fetch_patches(${PATCH_NAME} ${PATCH_PATH} ${DEBIAN_PATCH_URL} ${DEBIAN_PATCH_CHECKSUM} 3)
    prepare_patch_series("${DEBIAN_PATCH_SERIES}" ${PATCH_PATH})

    # These targets are from LLVMExports.cmake, so may vary by distribution.
    # in order to avoid fighting with what the LLVM package wants the linker to
    # do, it is easiest to just override the target link properties

    # These libraries are missing from the linker line command line
    # in the upstream package
    # Adding extra libraries here shouldn't affect the result, as they will be
    # ignored by the linker if not needed

    # It matters a lot what linker is being used. GNU toolchain accepts the
    # -Wl,--start-group option for avoiding circular dependencies in static
    # libs. Otherwise, with lld or other linkers, and it seems the default
    # behavior of lld (see) https://reviews.llvm.org/D43786 is to do this
    # anyays.
    #
    # For other linker, the order of static libraries is very significant, an
    # must be precomputed to find the correct non-circular permutation...
    set_target_properties(LLVMSupport PROPERTIES
      INTERFACE_LINK_LIBRARIES "LLVMCoroutines;LLVMCoverage;LLVMDebugInfoDWARF;LLVMDebugInfoPDB;LLVMDemangle;LLVMDlltoolDriver;LLVMFuzzMutate;LLVMInterpreter;LLVMLibDriver;LLVMLineEditor;LLVMLTO;LLVMMCA;LLVMMIRParser;LLVMObjCARCOpts;LLVMObjectYAML;LLVMOption;LLVMOptRemarks;LLVMPasses;LLVMPerfJITEvents;LLVMSymbolize;LLVMTableGen;LLVMTextAPI;LLVMWindowsManifest;LLVMXRay;-Wl,-Bstatic -ltinfo;"
    )

    # Need to omit lpthread here or it will try and link statically, and fail
    set_target_properties(LLVMCodeGen PROPERTIES
      INTERFACE_LINK_LIBRARIES "LLVMAnalysis;LLVMBitReader;LLVMBitWriter;LLVMCore;LLVMMC;LLVMProfileData;LLVMScalarOpts;LLVMSupport;LLVMTarget;LLVMTransformUtils"
    )

    set(CLANG_PATCH_COMMAND "(QUILT_PATCHES=${PATCH_PATH} quilt push -a || [[ $? -eq 2 ]])")
  endif()
  set(${patch_command} "${CLANG_PATCH_COMMAND}" PARENT_SCOPE)
endfunction(prepare_clang_patches patch_command)
