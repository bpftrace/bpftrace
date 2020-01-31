include(platforms/android)

# This file is for platform-specific configurations for embedded libraries.
# In general, these functions should set any necessary overrides for external
# projects need in order to build successfully for a target platform

# In general, functions here may set or override an external project step for:
# - Patching the sources
# - Adding or modifying configure flags, or setting the configure command
# - Modifying the build command or limiting the build targets
# - Installing the necessary headers or static libraries to a known prefix
function(libelf_platform_config patch_cmd configure_cmd build_cmd install_cmd)
  ProcessorCount(nproc)

  set(libelf_config_cmd CONFIGURE_COMMAND /bin/bash -xc
      "cd <BINARY_DIR> && \
       <SOURCE_DIR>/configure --prefix <INSTALL_DIR>/usr"
     )
  set(libelf_build_cmd BUILD_COMMAND /bin/bash -c
      "cd <BINARY_DIR>/lib && make -j${nproc} && \
       cd <BINARY_DIR>/libelf && make -j${nproc}"
     )
  set(libelf_install_cmd INSTALL_COMMAND /bin/bash -c "cd libelf && make install")

  get_target_triple(TARGET_TRIPLE)
  if(${TARGET_TRIPLE} MATCHES android)
    android_libelf_config(libelf_config_cmd)

    prepare_libelf_patches(LIBELF_ANDROID_PATCH_COMMAND)
    set(libelf_patch_cmd PATCH_COMMAND /bin/bash -c "${LIBELF_ANDROID_PATCH_COMMAND}")
  endif()

  set(${patch_cmd} "${libelf_patch_cmd}" PARENT_SCOPE)
  set(${configure_cmd} "${libelf_config_cmd}" PARENT_SCOPE)
  set(${build_cmd} "${libelf_build_cmd}" PARENT_SCOPE)
  set(${install_cmd} "${libelf_install_cmd}" PARENT_SCOPE)

endfunction(libelf_platform_config patch_cmd configure_cmd build_cmd install_cmd)

function(gnulib_platform_config patch_cmd configure_cmd build_cmd install_cmd)
  ProcessorCount(nproc)

  set(gnulib_config_cmd CONFIGURE_COMMAND /bin/bash -xc
      "<SOURCE_DIR>/gnulib-tool --create-testdir --lib='libargp' \
                                --dir=<SOURCE_DIR>/argp_sources argp && \
       <SOURCE_DIR>/argp_sources/configure --prefix <INSTALL_DIR>"
      ) # extra flags to configure needed


  # Doesn't support ninja so hardcode make
  set(gnulib_build_cmd BUILD_COMMAND /bin/bash -c "make -j${nproc}")

  set(gnulib_install_cmd INSTALL_COMMAND /bin/bash -c
      "mkdir -p <INSTALL_DIR>/lib <INSTALL_DIR>/include && \
      cp <BINARY_DIR>/gllib/libargp.a <INSTALL_DIR>/lib && \
      cp <SOURCE_DIR>/argp_sources/gllib/argp.h <INSTALL_DIR>/include"
     )

  set(gnulib_install_cmd INSTALL_COMMAND /bin/bash -c
      "mkdir -p <INSTALL_DIR>/lib <INSTALL_DIR>/include && \
      cp <BINARY_DIR>/gllib/libargp.a <INSTALL_DIR>/lib && \
      cp <SOURCE_DIR>/argp_sources/gllib/argp.h <INSTALL_DIR>/include/argp_real.h"
     )

  get_target_triple(TARGET_TRIPLE)

  if(${TARGET_TRIPLE} MATCHES android)
    android_gnulib_config(gnulib_config_cmd)
  endif()

  set(${patch_cmd} "${gnulib_patch_cmd}" PARENT_SCOPE)
  set(${configure_cmd} "${gnulib_config_cmd}" PARENT_SCOPE)
  set(${build_cmd} "${gnulib_build_cmd}" PARENT_SCOPE)
  set(${install_cmd} "${gnulib_install_cmd}" PARENT_SCOPE)
endfunction(gnulib_platform_config patch_cmd configure_cmd build_cmd install_cmd)

function(binutils_platform_config patch_cmd configure_cmd build_cmd install_cmd)
  if(${TARGET_TRIPLE} MATCHES android)
    android_binutils_config(binutils_config_cmd)
  endif()

  set(binutils_build_cmd BUILD_COMMAND /bin/bash -c
      "cd <BINARY_DIR>/bfd && make -j${nproc} && \
       cd <BINARY_DIR>/libiberty && make -j${nproc} && \
       cd <BINARY_DIR>/opcodes && make -j${nproc}"
     )
  set(binutils_install_cmd INSTALL_COMMAND /bin/bash -c
      "mkdir -p <INSTALL_DIR>/lib && mkdir -p <INSTALL_DIR>/include && \
       cp <BINARY_DIR>/bfd/libbfd.a <INSTALL_DIR>/lib && \
       cp <BINARY_DIR>/bfd/bfd.h <INSTALL_DIR>/include && \
       cp <BINARY_DIR>/opcodes/libopcodes.a <INSTALL_DIR>/lib && \
       cp <SOURCE_DIR>/include/dis-asm.h <INSTALL_DIR>/include && \
       cp <SOURCE_DIR>/include/ansidecl.h <INSTALL_DIR>/include && \
       cp <SOURCE_DIR>/include/symcat.h <INSTALL_DIR>/include && \
       cp <BINARY_DIR>/libiberty/libiberty.a <INSTALL_DIR>/lib"
     )
  set(${patch_cmd} "${binutils_patch_cmd}" PARENT_SCOPE)
  set(${configure_cmd} "${binutils_config_cmd}" PARENT_SCOPE)
  set(${build_cmd} "${binutils_build_cmd}" PARENT_SCOPE)
  set(${install_cmd} "${binutils_install_cmd}" PARENT_SCOPE)
endfunction(binutils_platform_config patch_cmd configure_cmd build_cmd install_cmd)

function(bcc_platform_config patch_cmd bcc_config_flags build_cmd install_cmd)
  ProcessorCount(nproc)

  if(EMBED_LIBELF)
    list(APPEND bcc_config_flags -DCMAKE_FIND_ROOT_PATH=${EMBEDDED_LIBELF_INSTALL_DIR})
  endif()

  if(EMBED_LLVM)
    list(APPEND bcc_config_flags -DLLVM_DIR=${EMBEDDED_LLVM_INSTALL_DIR}/lib/cmake/llvm)
  endif()

  if(EMBED_CLANG)
    list(APPEND bcc_config_flags -DCLANG_DIR=${EMBEDDED_CLANG_INSTALL_DIR})
  endif()

  list(APPEND bcc_config_flags -DEXTRA_INCLUDE_PATHS=${CMAKE_CURRENT_BINARY_DIR}/embedded_bcc-prefix/build_include/)
  list(APPEND bcc_config_flags -DPYTHON_CMD=python3.6) # FIXME hardcoded python version

  get_target_triple(TARGET_TRIPLE)
  if(${TARGET_TRIPLE} MATCHES android)
    list(APPEND bcc_config_flags -DCMAKE_TOOLCHAIN_FILE=/opt/android-ndk/build/cmake/android.toolchain.cmake)
    list(APPEND bcc_config_flags -DANDROID_ABI=${ANDROID_ABI})
    list(APPEND bcc_config_flags -DANDROID_NATIVE_API_LEVEL=${ANDROID_NATIVE_API_LEVEL})

    android_bcc_patch(bcc_patch_command)
    set(bcc_patch_cmd PATCH_COMMAND /bin/bash -c "${bcc_patch_command}")

    get_android_wordsize(PLATFORM_WORDSIZE)

    # Credit to @michalgr for this stub header
    set(BITS_H_HACK "\n\
#pragma once \n \
#ifndef __WORDSIZE \n \
#define __WORDSIZE ${PLATFORM_WORDSIZE} \n \
#endif\n")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/embedded_bcc-prefix/build_include/bits/reg.h "${LIBINTL_H_HACK}")
    file(COPY /usr/include/FlexLexer.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/embedded_bcc-prefix/build_include)
  endif()

  # Don't bother building anything but what we are explicitly using
  set(bcc_build_cmd BUILD_COMMAND /bin/bash -c "${CMAKE_MAKE_PROGRAM} -j${nproc} bcc-static bcc-loader-static bpf-static")

  # Based on reading the cmake file to get the headers to install, would be nice if
  # it had a header-install target :)
  set(bcc_install_cmd INSTALL_COMMAND /bin/bash -c " \
      mkdir -p <INSTALL_DIR>/lib <INSTALL_DIR>/include/bcc  \
               <INSTALL_DIR>/include/bpf \
               <INSTALL_DIR>/include/bcc/compat/linux  && \
      cp <BINARY_DIR>/src/cc/libbcc.a <INSTALL_DIR>/lib && \
      cp <BINARY_DIR>/src/cc/libbcc_bpf.a <INSTALL_DIR>/lib/libbpf.a && \
      cp <BINARY_DIR>/src/cc/libbcc-loader-static.a <INSTALL_DIR>/lib && \
      cp <SOURCE_DIR>/src/cc/libbpf.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/libbpf/src/libbpf.h <INSTALL_DIR>/include/bpf && \
      cp <SOURCE_DIR>/src/cc/libbpf/src/bpf.h <INSTALL_DIR>/include/bpf && \
      cp <SOURCE_DIR>/src/cc/libbpf/src/btf.h <INSTALL_DIR>/include/bpf && \
      cp <SOURCE_DIR>/src/cc/perf_reader.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/file_desc.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/table_desc.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/table_storage.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/bcc_common.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/bpf_module.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/bcc_exception.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/bcc_syms.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/bcc_proc.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/bcc_elf.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/bcc_usdt.h <INSTALL_DIR>/include/bcc && \
      cp <SOURCE_DIR>/src/cc/libbpf/include/uapi/linux/*.h <INSTALL_DIR>/include/bcc/compat/linux"
    )

  set(${patch_cmd} "${bcc_patch_cmd}" PARENT_SCOPE)
  set(BCC_CONFIGURE_FLAGS "${bcc_config_flags}" PARENT_SCOPE) # FIXME leaky, should the var name be passed separately?
  set(${build_cmd} "${bcc_build_cmd}" PARENT_SCOPE)
  set(${install_cmd} "${bcc_install_cmd}" PARENT_SCOPE)

endfunction(bcc_platform_config patch_cmd configure_cmd build_cmd install_cmd)

function(llvm_platform_config patch_cmd configure_flags build_cmd install_cmd)

  get_target_triple(TARGET_TRIPLE)
  if(${TARGET_TRIPLE} MATCHES android)
    ProcessorCount(nproc)
    list(APPEND configure_flags -DCMAKE_TOOLCHAIN_FILE=/opt/android-ndk/build/cmake/android.toolchain.cmake)
    list(APPEND configure_flags -DANDROID_ABI=${ANDROID_ABI})
    list(APPEND configure_flags -DANDROID_NATIVE_API_LEVEL=${ANDROID_NATIVE_API_LEVEL})

    # LLVMHello doesn't work, but is part of the all target.
    # To get around this, each target is instead built individually, omitting LLVMHello
    # A side effet of this is progress is reported per target
    # FIXME is there a way to trick Make into omitting just LLVMHello? -W maybe?
    string(REPLACE ";" " " LLVM_MAKE_TARGETS "${LLVM_LIBRARY_TARGETS}" )
    set(llvm_build_cmd BUILD_COMMAND /bin/bash -c
                            "${CMAKE_MAKE_PROGRAM} -j${nproc} ${LLVM_MAKE_TARGETS} ")

    set(llvm_install_cmd INSTALL_COMMAND /bin/bash -c
        "mkdir -p <INSTALL_DIR>/lib/ <INSTALL_DIR>/bin/ && \
         find <BINARY_DIR>/lib/ | grep '\\.a$' | \
         xargs -I@ cp @ <INSTALL_DIR>/lib/ && \
         ${CMAKE_MAKE_PROGRAM} install-cmake-exports && \
         ${CMAKE_MAKE_PROGRAM} install-llvm-headers && \
         cp <BINARY_DIR>/NATIVE/bin/llvm-tblgen <INSTALL_DIR>/bin/ "
       )
  endif()

  set(LLVM_CONFIGURE_FLAGS "${configure_flags}" PARENT_SCOPE) # FIXME leaky, should the var name be passed separately?
  set(${build_cmd} "${llvm_build_cmd}" PARENT_SCOPE)
  set(${install_cmd} "${llvm_install_cmd}" PARENT_SCOPE)
endfunction(llvm_platform_config patch_cmd configure_flags build_cmd install_cmd)

function(clang_platform_config patch_cmd lib_targets configure_flags build_cmd install_cmd)
  ProcessorCount(nproc)
  # Clang always needs a custom install command, because libclang isn't installed
  # by the all target.
  set(libclang_install_command
      "mkdir -p <INSTALL_DIR>/lib/ && \
      cp <BINARY_DIR>/lib/libclang.a <INSTALL_DIR>/lib/libclang.a"
     )

  set(clang_install_cmd INSTALL_COMMAND /bin/bash -c
      "${CMAKE_MAKE_PROGRAM} -j ${nproc} install && \
       ${libclang_install_command}"
     )

  if(NOT EMBED_LLVM)
    # If not linking and building against embedded LLVM, patches may need to
    # be applied to link with the distribution LLVM. This is handled by a
    # helper function
    prepare_clang_patches(patch_command)
    set(clang_patch_cmd PATCH_COMMAND /bin/bash -c "${patch_command}")
  endif()

  if(EMBED_LIBCLANG_ONLY)
    set(clang_build_cmd BUILD_COMMAND /bin/bash -c "${CMAKE_MAKE_PROGRAM} libclang_static -j${nproc}")
    set(clang_install_cmd INSTALL_COMMAND /bin/bash -c "${libclang_install_command}")
  endif()

  get_host_triple(HOST_TRIPLE)
  get_target_triple(TARGET_TRIPLE)
  if(NOT "${HOST_TRIPLE}" STREQUAL "${TARGET_TRIPLE}")
    set(CROSS_COMPILING_CLANG ON)
  endif()

  if(${CROSS_COMPILING_CLANG})
    ProcessorCount(nproc)

    # If cross-compling, a host architecture clang-tblgen is needed, and not
    # provided by standard packages. Unlike LLVM, clang isn't smart enough to
    # bootstrap this for itself
    ExternalProject_Add(embedded_clang_host
      URL "${CLANG_DOWNLOAD_URL}"
      URL_HASH "${CLANG_URL_CHECKSUM}"
      BUILD_COMMAND /bin/bash -c "${CMAKE_MAKE_PROGRAM} -j${nproc} clang-tblgen"
      INSTALL_COMMAND /bin/bash -c "mkdir -p <INSTALL_DIR>/bin && \
                                    cp <BINARY_DIR>/bin/clang-tblgen <INSTALL_DIR>/bin"
      BUILD_BYPRODUCTS <INSTALL_DIR>/bin/clang-tblgen
      UPDATE_DISCONNECTED 1
      DOWNLOAD_NO_PROGRESS 1
    ) # FIXME set build byproducts for ninja

    ExternalProject_Get_Property(embedded_clang_host INSTALL_DIR)
    set(CLANG_TBLGEN_PATH "${INSTALL_DIR}/bin/clang-tblgen")

    list(APPEND configure_flags -DCLANG_TABLEGEN=${CLANG_TBLGEN_PATH})
  endif()

  if(${TARGET_TRIPLE} MATCHES android)
    ProcessorCount(nproc)

    if(EMBED_LIBCLANG_ONLY)
      message(FATAL_ERROR "Cannot set EMBED_LIBCLANG_ONLY on Android, no system libs to link.")
    endif()

    list(APPEND configure_flags -DCMAKE_TOOLCHAIN_FILE=/opt/android-ndk/build/cmake/android.toolchain.cmake)
    list(APPEND configure_flags -DANDROID_ABI=${ANDROID_ABI})
    list(APPEND configure_flags -DANDROID_NATIVE_API_LEVEL=${ANDROID_NATIVE_API_LEVEL})
    list(APPEND configure_flags -DCMAKE_CROSSCOMPILING=True)

    string(REPLACE ";" " " CLANG_MAKE_TARGETS "${lib_targets}")
    set(clang_build_cmd BUILD_COMMAND /bin/bash -c
        "${CMAKE_MAKE_PROGRAM} -j${nproc} libclang_static && \
         ${CMAKE_MAKE_PROGRAM} -j${nproc} ${CLANG_MAKE_TARGETS}"
       )

    # Clang may fail to build some shared libraries as part of its install all
    # so like with LLVM we'll just grab what we need.
    set(clang_install_cmd INSTALL_COMMAND /bin/bash -c
        "mkdir -p <INSTALL_DIR>/lib/ <INSTALL_DIR>/bin/ && \
         find <BINARY_DIR>/lib/ | grep '\\.a$' | \
         xargs -I@ cp @ <INSTALL_DIR>/lib/ && \
         cp -r <SOURCE_DIR>/include/ <INSTALL_DIR>/ && \
         cd <BINARY_DIR> && find . | grep .inc$ | xargs -I@ cp @ <INSTALL_DIR>/@"
       )

  endif()

  set(CLANG_CONFIGURE_FLAGS "${configure_flags}" PARENT_SCOPE) # FIXME leaky, should the var name be passed separately?
  set(${build_cmd} "${clang_build_cmd}" PARENT_SCOPE)
  set(${install_cmd} "${clang_install_cmd}" PARENT_SCOPE)
  set(${patch_cmd} "${clang_patch_cmd}" PARENT_SCOPE)
endfunction(clang_platform_config patch_cmd configure_flags build_cmd install_cmd)
