if(NOT EMBED_LIBELF)
  return()
endif()
include(embed_helpers)

set(ELFUTILS_VERSION 0.176)
set(ELFUTILS_DOWNLOAD_URL "http://sourceware.org/pub/elfutils/${ELFUTILS_VERSION}/elfutils-${ELFUTILS_VERSION}.tar.bz2")
set(ELFUTILS_CHECKSUM "SHA256=eb5747c371b0af0f71e86215a5ebb88728533c3a104a43d4231963f308cd1023")

# FIXME Maybe check if argp is available and include based on that instead?
get_target_triple(TARGET_TRIPLE)
if(${TARGET_TRIPLE} MATCHES android)
  include(embed_gnulib)
endif()

libelf_platform_config(LIBELF_PATCH_COMMAND
                       LIBELF_CONFIGURE_COMMAND
                       LIBELF_BUILD_COMMAND
                       LIBELF_INSTALL_COMMAND)

# We don't need to precompute build byproducts, as Ninja can't be used with
# automake projects
ExternalProject_Add(embedded_libelf
  URL "${ELFUTILS_DOWNLOAD_URL}"
  URL_HASH "${ELFUTILS_CHECKSUM}"
  ${LIBELF_PATCH_COMMAND}
  ${LIBELF_CONFIGURE_COMMAND}
  ${LIBELF_BUILD_COMMAND}
  ${LIBELF_INSTALL_COMMAND}
  UPDATE_DISCONNECTED 1
  DOWNLOAD_NO_PROGRESS 1
)

# FIXME set library targets and dependencies here so that dependencies are done properly

# FIXME only if cross compiling maybe? Or check if library not found?
ExternalProject_Add_StepDependencies(embedded_libelf install embedded_gnulib)

ExternalProject_Get_Property(embedded_libelf INSTALL_DIR)
set(EMBEDDED_LIBELF_INSTALL_DIR ${INSTALL_DIR})

# Add the library to cmake as a library target, and set it to depend on the
# external project
add_library(elf STATIC IMPORTED)
set_property(TARGET elf PROPERTY IMPORTED_LOCATION "${EMBEDDED_LIBELF_INSTALL_DIR}/lib/libelf.a")
add_dependencies(elf embedded_libelf)
