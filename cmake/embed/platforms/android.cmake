function(android_libelf_config libelf_config_cmd)

  # Credit to @michalgr for this header
  set(LIBINTL_H_HACK "\n\
#ifndef LIBINTL_H \n\
#define LIBINTL_H \n\
 \
// libintl.h is included in a lot of sources in efutils, but provided \n\
// functionalities are not really necessary. Because of that we follow \n\
// the AOSP example and provide a fake header turning some functions into \n\
// nops with macros \n\
 \n\
#define gettext(x)      (x) \n\
#define dgettext(x,y)   (y) \n\
 \n\
#endif")
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/embedded_libelf-prefix/build_include/libintl.h "${LIBINTL_H_HACK}")

  get_toolchain_exports(CROSS_EXPORTS)
  set(ELFUTILS_CROSS_EXPORTS
      "${CROSS_EXPORTS} && \
      export LDFLAGS=-L${EMBEDDED_GNULIB_INSTALL_DIR}/lib && \
      export CFLAGS=-I${EMBEDDED_GNULIB_INSTALL_DIR}/include && \
      export CFLAGS=\"$CFLAGS -I<INSTALL_DIR>/build_include\" && \
      export CFLAGS=\"$CFLAGS -Dprogram_invocation_short_name=\\\\\\\"no-program_invocation_short_name\\\\\\\"\""
                                                                              # smh this much escaping
     )

  get_android_cross_tuple(ANDROID_CROSS_TRIPLE)
  set(${libelf_config_cmd} CONFIGURE_COMMAND /bin/bash -xc
     "${ELFUTILS_CROSS_EXPORTS} && \
      cd <BINARY_DIR> && \
      <SOURCE_DIR>/configure --host ${ANDROID_CROSS_TRIPLE} --prefix <INSTALL_DIR>/usr"
     PARENT_SCOPE)
endfunction(android_libelf_config libelf_config_cmd)

function(android_gnulib_config gnulib_config_cmd)
    # Credit to @michalgr for this stub header
    set(ARGP_HEADER_WRAPPER "\
#ifndef ARGP_WRAPPER_H\n\
#define ARGP_WRAPPER_H\n\
#ifndef ARGP_EI\n\
#  define ARGP_EI inline\n\
#endif\n\
// since ece81a73b64483a68f5157420836d84beb3a1680 argp.h as distributed with\n\
// gnulib requires _GL_INLINE_HEADER_BEGIN macro to be defined.\n\
#ifndef _GL_INLINE_HEADER_BEGIN\n\
#  define _GL_INLINE_HEADER_BEGIN\n\
#  define _GL_INLINE_HEADER_END\n\
#endif\n\
#include \"argp_real.h\"\n\
#endif")

    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/embedded_gnulib-prefix/include/argp.h "${ARGP_HEADER_WRAPPER}")

    get_toolchain_exports(CROSS_EXPORTS)
    get_android_cross_tuple(ANDROID_CROSS_TRIPLE)
    # Patch for argp header here
    set(${gnulib_config_cmd} CONFIGURE_COMMAND /bin/bash -xc
        "<SOURCE_DIR>/gnulib-tool --create-testdir --lib='libargp' \
                                  --dir=<SOURCE_DIR>/argp_sources argp && \
        ${CROSS_EXPORTS} && \
        <SOURCE_DIR>/argp_sources/configure --host ${ANDROID_CROSS_TRIPLE} \
                                            --prefix <INSTALL_DIR>" # FIXME hardcoded abi
       PARENT_SCOPE) # extra flags to configure needed
endfunction(android_gnulib_config gnulib_config_cmd)

function(android_binutils_config binutils_config_cmd)

  get_toolchain_exports(CROSS_EXPORTS)
  get_android_cross_tuple(ANDROID_CROSS_TRIPLE) # FIXME only do this on android
  set(${binutils_config_cmd} CONFIGURE_COMMAND /bin/bash -xc
      "${CROSS_EXPORTS} && \
       mkdir -p <BINARY_DIR>/bfd <BINARY_DIR>/opcodes \
                <BINARY_DIR>/libiberty <BINARY_DIR>/zlib && \
       cd <BINARY_DIR>/zlib && \
       <SOURCE_DIR>/zlib/configure --host ${ANDROID_CROSS_TRIPLE} \
                                  --prefix <INSTALL_DIR> && \
       mkdir -p <BINARY_DIR>/bfd <BINARY_DIR>/opcodes <BINARY_DIR>/libiberty && \
       cd <BINARY_DIR>/bfd && \
       <SOURCE_DIR>/bfd/configure --host ${ANDROID_CROSS_TRIPLE} \
                                  --prefix <INSTALL_DIR> && \
       cd <BINARY_DIR>/libiberty && \
       <SOURCE_DIR>/libiberty/configure --host ${ANDROID_CROSS_TRIPLE} \
                                  --prefix <INSTALL_DIR> && \
       cd <BINARY_DIR>/opcodes && \
       <SOURCE_DIR>/opcodes/configure --host ${ANDROID_CROSS_TRIPLE} \
                                  --prefix <INSTALL_DIR>"
     PARENT_SCOPE)
endfunction(android_binutils_config binutils_config_cmd)

function(android_bcc_config bcc_config_flags)
endfunction(android_bcc_config bcc_config_flags)

function(android_bcc_patch patch_command)
  get_target_triple(TARGET_TRIPLE)

  # FIXME maybe check BCC version and bail / warn if not 0.12.0?
  if(${TARGET_TRIPLE} MATCHES android)
    set(BCC_ANDROID_PATCH_URL "https://gist.github.com/dalehamel/da2f73357cd8cc4e60a1218e562a472b/archive/f0180ba9a44db1f4da22b3a3be2d763ab9c0b716.tar.gz")
    set(BCC_ANDROID_PATCH_CHECKSUM ba5a8a6f567eede61f4df4d468ff6d0faa3a7675be805817bed036eaa597324d)

    set(PATCH_NAME "bcc-patches.tar.gz")
    set(PATCH_PATH "${CMAKE_CURRENT_BINARY_DIR}/bcc-android/")

    set(BCC_ANDROID_PATCH_SERIES "")
    list(APPEND BCC_ANDROID_PATCH_SERIES "android-bionic-poll-t.patch")
    list(APPEND BCC_ANDROID_PATCH_SERIES "bcc-cmakelist-android.patch -p2")

    list(LENGTH BCC_ANDROID_PATCH_SERIES NUM_PATCHES)
    message("${NUM_PATCHES} patches will be applied for BCC to build correctly for Android.")
    fetch_patches(${PATCH_NAME} ${PATCH_PATH} ${BCC_ANDROID_PATCH_URL} ${BCC_ANDROID_PATCH_CHECKSUM} 1)
    prepare_patch_series("${BCC_ANDROID_PATCH_SERIES}" ${PATCH_PATH})
    set(BCC_ANDROID_PATCH_COMMAND "(QUILT_PATCHES=${PATCH_PATH} quilt push -a || [[ $? -eq 2 ]])")
  endif()
  set(${patch_command} "${BCC_ANDROID_PATCH_COMMAND}" PARENT_SCOPE)
endfunction(android_bcc_patch patch_command)
