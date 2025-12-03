if(HAVE_BFD_DISASM)
  set(BFD_DISASM_SRC bfd-disasm.cpp)
endif()

if (BUILD_UBSAN)
  # This adds -fsanitize=undefined to all below compiler invocations, including
  # subdirectories.
  add_compile_options("-fsanitize=undefined")
endif()

add_library(required_resources required_resources.cpp)
add_dependencies(required_resources parser)

add_library(compiler_core STATIC
  functions.cpp
  struct.cpp
  types.cpp
)
add_dependencies(compiler_core parser)

add_library(runtime STATIC
  async_action.cpp
  attached_probe.cpp
  bpffeature.cpp
  bpftrace.cpp
  bpfbytecode.cpp
  bpfmap.cpp
  bpfprogram.cpp
  btf.cpp
  child.cpp
  config.cpp
  disasm.cpp
  dwarf_parser.cpp
  format_string.cpp
  globalvars.cpp
  kernel_types.cpp
  log.cpp
  probe_matcher.cpp
  probe_types.cpp
  procmon.cpp
  run_bpftrace.cpp
  usdt.cpp
  pcap_writer.cpp
  types_format.cpp
  ksyms.cpp
  usyms.cpp
  ${BFD_DISASM_SRC}
)
# Ensure flex+bison outputs are built first
add_dependencies(runtime parser)

add_library(libbpftrace STATIC
  build_info.cpp
  driver.cpp
  lockdown.cpp
)
# So it's not "liblibbpftrace"
set_target_properties(libbpftrace PROPERTIES PREFIX "")

add_executable(bpftrace
  main.cpp
  benchmark.cpp
)

# TODO: Honor `STATIC_LINKING` properly.
if(LIBBLAZESYM_FOUND)
  target_link_libraries(runtime ${LIBBLAZESYM_LIBRARIES})
endif()

install(TARGETS bpftrace DESTINATION ${CMAKE_INSTALL_BINDIR})
target_compile_definitions(bpftrace PRIVATE ${BPFTRACE_FLAGS})

# TODO(Jiawei Zhao): this conditional can be removed when we no longer use bcc.
if(STATIC_LINKING)
  target_link_libraries(bpftrace libbpftrace)
else()
  target_link_libraries(bpftrace libbpftrace ${LIBBPF_LIBRARIES})
endif(STATIC_LINKING)

# compile definitions

# This is run on every build to ensure the version string is always up-to-date
add_custom_target(version_h
  COMMAND ${CMAKE_COMMAND}
    -DVERSION_H_IN=${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
    -DVERSION_H=${CMAKE_BINARY_DIR}/version.h
    -Dbpftrace_VERSION_MAJOR=${bpftrace_VERSION_MAJOR}
    -Dbpftrace_VERSION_MINOR=${bpftrace_VERSION_MINOR}
    -Dbpftrace_VERSION_PATCH=${bpftrace_VERSION_PATCH}
    -Dbpftrace_SOURCE_DIR=${CMAKE_SOURCE_DIR}
    -P ${CMAKE_SOURCE_DIR}/cmake/Version.cmake
)
add_dependencies(runtime version_h)
add_dependencies(bpftrace version_h)
add_dependencies(libbpftrace version_h)

target_compile_definitions(required_resources PRIVATE ${BPFTRACE_FLAGS})
target_compile_definitions(runtime PRIVATE ${BPFTRACE_FLAGS})
target_include_directories(libbpftrace PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_definitions(libbpftrace PRIVATE ${BPFTRACE_FLAGS})

# Linking
if(STATIC_LINKING)
  target_link_options(bpftrace BEFORE PRIVATE "-static-libgcc" "-static-libstdc++")
endif(STATIC_LINKING)


target_link_libraries(runtime debugfs output tracefs util providers)
target_link_libraries(runtime ${LIBBPF_LIBRARIES} ${ZLIB_LIBRARIES})
target_link_libraries(libbpftrace parser runtime aot ast arch util cxxdemangler_llvm)

if(LIBPCAP_FOUND)
  target_link_libraries(libbpftrace ${LIBPCAP_LIBRARIES})
endif(LIBPCAP_FOUND)

if(HAVE_BFD_DISASM)
  if(STATIC_LINKING OR LIBBFD_STATIC)
    add_library(LIBBFD STATIC IMPORTED)
    set_property(TARGET LIBBFD PROPERTY IMPORTED_LOCATION ${LIBBFD_LIBRARIES})
    target_link_libraries(runtime LIBBFD)
    add_library(LIBOPCODES STATIC IMPORTED)
    set_property(TARGET LIBOPCODES PROPERTY IMPORTED_LOCATION ${LIBOPCODES_LIBRARIES})
    target_link_libraries(runtime LIBOPCODES)
    add_library(LIBIBERTY STATIC IMPORTED)
    set_property(TARGET LIBIBERTY PROPERTY IMPORTED_LOCATION ${LIBIBERTY_LIBRARIES})
    target_link_libraries(runtime LIBIBERTY)

    add_library(LIBZSTD STATIC IMPORTED)
    if (LIBZSTD_LIBRARIES)
      set_property(TARGET LIBZSTD PROPERTY IMPORTED_LOCATION ${LIBZSTD_LIBRARIES})
      target_link_libraries(runtime LIBZSTD)
    endif(LIBZSTD_LIBRARIES)

    add_library(LIBSFRAME STATIC IMPORTED)
    if (LIBSFRAME_LIBRARIES)
      set_property(TARGET LIBSFRAME PROPERTY IMPORTED_LOCATION ${LIBSFRAME_LIBRARIES})
      target_link_libraries(runtime LIBSFRAME)
    endif(LIBSFRAME_LIBRARIES)
  else()
    target_link_libraries(runtime ${LIBBFD_LIBRARIES})
    target_link_libraries(runtime ${LIBOPCODES_LIBRARIES})
  endif(STATIC_LINKING OR LIBBFD_STATIC)
endif(HAVE_BFD_DISASM)

# Link to bcc libraries (without LLVM) if possible
if(LIBBCC_BPF_CONTAINS_RUNTIME)
  target_link_libraries(runtime ${LIBBCC_BPF_LIBRARIES})
else()
  target_link_libraries(runtime ${LIBBCC_LIBRARIES})
endif()

if(STATIC_LINKING)
  # These are not part of the static libbcc so have to be added separate
  target_link_libraries(runtime ${LIBBCC_BPF_LIBRARIES})
  target_link_libraries(runtime ${LIBBPF_LIBRARIES})
  target_link_libraries(runtime ${LIBBCC_LOADER_LIBRARY_STATIC})

  find_package(LibLzma)
  add_library(LIBLZMA STATIC IMPORTED)
  set_property(TARGET LIBLZMA PROPERTY IMPORTED_LOCATION ${LIBLZMA_LIBRARIES})
  target_link_libraries(runtime LIBLZMA)

  add_library(LIBELF STATIC IMPORTED)
  set_property(TARGET LIBELF PROPERTY IMPORTED_LOCATION ${LIBELF_LIBRARIES})
  target_link_libraries(runtime LIBELF)
else()
  target_link_libraries(runtime ${LIBELF_LIBRARIES})
endif(STATIC_LINKING)

if (LIBDW_FOUND)
  if(STATIC_LINKING)
    find_package(LibBz2)
    find_package(LibEbl)

    add_library(LIBBZ2 STATIC IMPORTED)
    set_property(TARGET LIBBZ2 PROPERTY IMPORTED_LOCATION ${LIBBZ2_LIBRARIES})

    add_library(LIBDW STATIC IMPORTED)
    set_property(TARGET LIBDW PROPERTY IMPORTED_LOCATION ${LIBDW_LIBRARIES})

    set(LIBDW_LIBS LIBBZ2 LIBELF LIBLZMA)

    if (${LIBEBL_FOUND})
      # libebl is not necessary on some systems (e.g. Alpine)
      add_library(LIBEBL STATIC IMPORTED)
      set_property(TARGET LIBEBL PROPERTY IMPORTED_LOCATION ${LIBEBL_LIBRARIES})
      set(LIBDW_LIBS ${LIBDW_LIBS} LIBEBL)
    endif()

    target_link_libraries(LIBDW INTERFACE ${LIBDW_LIBS})

    target_link_libraries(runtime LIBDW)
  else()
    target_link_libraries(runtime ${LIBDW_LIBRARIES})
  endif()
endif()

# Support for std::filesystem
# GCC version <9 and Clang (all versions) require -lstdc++fs
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR ${CMAKE_CXX_COMPILER_VERSION} VERSION_LESS "9")
  target_link_libraries(runtime "stdc++fs")
  target_link_libraries(libbpftrace "stdc++fs")
endif()

if (BUILD_ASAN)
  target_compile_options(bpftrace PUBLIC "-fsanitize=address")
  target_link_options(bpftrace PUBLIC "-fsanitize=address")
endif()

if (BUILD_UBSAN)
  # We do not use add_link_options here since it doesn't work for some reason.
  # Instead, just pass -fsanitize=undefined to the linker when linking the
  # bpftrace target.
  target_link_options(bpftrace PUBLIC "-fsanitize=undefined")
endif()

if (STATIC_LINKING)
  if(ANDROID)
    target_link_libraries(libbpftrace "-Wl,-Bdynamic" "-ldl" "-lm" "-lz")
    target_link_libraries(runtime "-Wl,-Bdynamic" "-ldl" "-lm" "-lz")
  else()
    target_link_libraries(libbpftrace "-Wl,-Bdynamic" "-lrt" "-lpthread" "-ldl" "-lm")
    target_link_libraries(libbpftrace "-Wl,-Bstatic" "-lz")
    target_link_libraries(runtime "-Wl,-Bdynamic" "-lrt" "-lpthread" "-ldl" "-lm")
    target_link_libraries(runtime "-Wl,-Bstatic" "-lz")
  endif()
endif()

if (ENABLE_SYSTEMD)
  target_link_libraries(runtime PkgConfig::libsystemd)
endif()

unset(BPFTRACE)

add_subdirectory(aot)
add_subdirectory(arch)
add_subdirectory(ast)
add_subdirectory(btf)
add_subdirectory(cxxdemangler)
add_subdirectory(debugfs)
add_subdirectory(output)
add_subdirectory(providers)
add_subdirectory(stdlib)
add_subdirectory(tracefs)
add_subdirectory(util)
