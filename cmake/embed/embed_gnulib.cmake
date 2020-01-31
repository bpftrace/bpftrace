# gnulib is only a build-time dependency of libelf, and even we only build argp.a
# So far this is mostly useful for cross compiling, to easily build libelf without
# patching it to avoid this dependency.
if(NOT EMBED_LIBELF)
  return()
endif()

include(embed_helpers)

set(GNULIB_DOWNLOAD_URL "http://git.savannah.gnu.org/gitweb/?p=gnulib.git&a=snapshot&h=cd46bf0ca5083162f3ac564ebbdeb6371085df45&sf=tgz")
set(GNULIB_CHECKSUM "SHA256=b355951d916eda73f0e7fb9d828623c09185b6624073492d7de88726c6aa6753")

gnulib_platform_config(GNULIB_PATCH_COMMAND
                       GNULIB_CONFIGURE_COMMAND
                       GNULIB_BUILD_COMMAND
                       GNULIB_INSTALL_COMMAND)

ExternalProject_Add(embedded_gnulib
  URL "${GNULIB_DOWNLOAD_URL}"
  URL_HASH "${GNULIB_CHECKSUM}"
  ${GNULIB_PATCH_COMMAND}
  ${GNULIB_CONFIGURE_COMMAND}
  ${GNULIB_BUILD_COMMAND}
  ${GNULIB_INSTALL_COMMAND}
  UPDATE_DISCONNECTED 1
  DOWNLOAD_NO_PROGRESS 1
)

ExternalProject_Get_Property(embedded_gnulib INSTALL_DIR)
set(EMBEDDED_GNULIB_INSTALL_DIR ${INSTALL_DIR})
