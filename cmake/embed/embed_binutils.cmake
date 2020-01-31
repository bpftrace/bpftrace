if(NOT EMBED_BINUTILS)
  return()
endif()
include(embed_helpers)

# The only time binutils should ever need to be embedded is when cross-compiling
# Have a check that asserts this
# It doesn't look like these dependencies are actually required, so need to verify
# this, may only be needed for btf? Build it anyways, but lower priority to figure out

set(BINUTILS_VERSION "2.27") # This is what the android toolchain uses for r21 pre
set(BINUTILS_DOWNLOAD_URL "https://ftp.gnu.org/gnu/binutils/binutils-${BINUTILS_VERSION}.tar.gz")
set(BINUTILS_CHECKSUM "SHA256=26253bf0f360ceeba1d9ab6965c57c6a48a01a8343382130d1ed47c468a3094f")

# Only build binutils targets that are explicitly needed
set(BINUTILS_LIBRARY_TARGETS
    bfd
    iberty
    opcodes
   )

binutils_platform_config(BINUTILS_PATCH_COMMAND
                         BINUTILS_CONFIGURE_COMMAND
                         BINUTILS_BUILD_COMMAND
                         BINUTILS_INSTALL_COMMAND)

ExternalProject_Add(embedded_binutils
  URL "${BINUTILS_DOWNLOAD_URL}"
  URL_HASH "${BINUTILS_CHECKSUM}"
  ${BINUTILS_CONFIGURE_COMMAND}
  ${BINUTILS_BUILD_COMMAND}
  ${BINUTILS_INSTALL_COMMAND}
  UPDATE_DISCONNECTED 1
  DOWNLOAD_NO_PROGRESS 1
)

ExternalProject_Get_Property(embedded_binutils INSTALL_DIR)
set(EMBEDDED_BINUTILS_INSTALL_DIR ${INSTALL_DIR})

foreach(binutils_target IN LISTS BINUTILS_LIBRARY_TARGETS)
  list(APPEND BINUTILS_EMBEDDED_CMAKE_TARGETS ${binutils_target})
  add_library(${binutils_target} STATIC IMPORTED)
  set(binutils_target_path "${EMBEDDED_BINUTILS_INSTALL_DIR}/lib/lib${binutils_target}.a")
  set_property(TARGET ${binutils_target} PROPERTY IMPORTED_LOCATION "${binutils_target_path}")
  add_dependencies(${binutils_target} embedded_binutils)
endforeach(binutils_target)
