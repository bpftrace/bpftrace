if(NOT EMBED_BCC)
  return()
endif()

set(BCC_VERSION "v0.12.0")
set(BCC_DOWNLOAD_URL "https://github.com/iovisor/bcc/releases/download/${BCC_VERSION}/bcc-src-with-submodule.tar.gz")
set(BCC_CHECKSUM "SHA256=a7acf0e7a9d3ca03a91f22590e695655a5f0ccf8e3dc29e454c2e4c5d476d8aa")

set(BCC_LIBRARY_TARGETS
    bcc
    bcc-loader-static
    bcc_bpf
   )

set(BCC_CONFIGURE_FLAGS
    -Wno-dev
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    )

bcc_platform_config(BCC_PATCH_COMMAND
                    "${BCC_CONFIGURE_FLAGS}"
                    BCC_BUILD_COMMAND
                    BCC_INSTALL_COMMAND)

# Compute the build byproducts for Ninja ahead of time
set(BCC_TARGET_LIBS "")
foreach(bcc_target IN LISTS BCC_LIBRARY_TARGETS)
  if("${bcc_target}" STREQUAL "bcc_bpf")
  list(APPEND BCC_TARGET_LIBS "<INSTALL_DIR>/lib/libbpf.a")
  else()
  list(APPEND BCC_TARGET_LIBS "<INSTALL_DIR>/lib/lib${bcc_target}.a")
  endif()
endforeach(bcc_target)

ExternalProject_Add(embedded_bcc
  URL "${BCC_DOWNLOAD_URL}"
  URL_HASH "${BCC_CHECKSUM}"
  CMAKE_ARGS "${BCC_CONFIGURE_FLAGS}"
  ${BCC_PATCH_COMMAND}
  ${BCC_BUILD_COMMAND}
  ${BCC_INSTALL_COMMAND}
  BUILD_BYPRODUCTS ${BCC_TARGET_LIBS}
  UPDATE_DISCONNECTED 1
  DOWNLOAD_NO_PROGRESS 1
)

if(EMBED_LIBELF)
  ExternalProject_Add_StepDependencies(embedded_bcc install embedded_libelf)
endif()

if(EMBED_LLVM)
  ExternalProject_Add_StepDependencies(embedded_bcc install embedded_llvm)
endif()

if(EMBED_CLANG)
  ExternalProject_Add_StepDependencies(embedded_bcc install embedded_clang)
endif()

ExternalProject_Get_Property(embedded_bcc INSTALL_DIR)
set(EMBEDDED_BCC_INSTALL_DIR ${INSTALL_DIR})

foreach(bcc_target IN LISTS BCC_LIBRARY_TARGETS)
  list(APPEND BCC_EMBEDDED_CMAKE_TARGETS ${bcc_target})
  add_library(${bcc_target} STATIC IMPORTED)

  # If libbpf is from bcc (which is currently the convention), it needs to be
  # renamed to bpf as part of the install process, this handles this quirk
  if( "${bcc_target}" STREQUAL "bcc_bpf" )
    set(bcc_target_path "${EMBEDDED_BCC_INSTALL_DIR}/lib/libbpf.a")
  else()
    set(bcc_target_path "${EMBEDDED_BCC_INSTALL_DIR}/lib/lib${bcc_target}.a")
  endif()

  set_property(TARGET ${bcc_target} PROPERTY IMPORTED_LOCATION "${bcc_target_path}")
  add_dependencies(${bcc_target} embedded_llvm)
endforeach(bcc_target)
