if(HAVE_BFD_DISASM)
  set(BFD_DISASM_SRC bfd-disasm.cpp)
endif()

if(BUILD_FUZZ)
  message(STATUS "Build for fuzzing")
  set(MAIN_SRC fuzz_main.cpp)
  set(BPFTRACE bpftrace_fuzz)
else()
  set(MAIN_SRC main.cpp)
  if (NOT DEFINED BPFTRACE)
    set(BPFTRACE bpftrace)
  endif ()
endif()

add_library(required_resources required_resources.cpp)
add_dependencies(required_resources parser)

add_library(runtime
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
  log.cpp
  mapkey.cpp
  output.cpp
  probe_matcher.cpp
  procmon.cpp
  printf.cpp
  resolve_cgroupid.cpp
  run_bpftrace.cpp
  struct.cpp
  tracefs.cpp
  debugfs.cpp
  types.cpp
  usdt.cpp
  utils.cpp
  pcap_writer.cpp
  ${BFD_DISASM_SRC}
)
# Ensure flex+bison outputs are built first
add_dependencies(runtime parser)

add_library(libbpftrace
  build_info.cpp
  clang_parser.cpp
  driver.cpp
  lockdown.cpp
  tracepoint_format_parser.cpp
)
# So it's not "liblibbpftrace"
set_target_properties(libbpftrace PROPERTIES PREFIX "")

add_executable(${BPFTRACE}
  ${MAIN_SRC}
)
target_include_directories(${BPFTRACE} PUBLIC ${CMAKE_BINARY_DIR}/src)

install(TARGETS ${BPFTRACE} DESTINATION ${CMAKE_INSTALL_BINDIR})
target_link_libraries(${BPFTRACE} libbpftrace)

if (BUILD_FUZZ)
  target_compile_options(${BPFTRACE} PUBLIC "-DFUZZ")

  if(FUZZ_TARGET STREQUAL "semantic")
      message(STATUS "Fuzzing seantic analyzer")
      target_compile_options(${BPFTRACE} PUBLIC -DTEST_SEMANTIC)
  elseif(FUZZ_TARGET STREQUAL "codegen")
      message(STATUS "Fuzzing codegen")
  else()
      message(FATAL_ERROR "Unsupported FUZZ_TARGET")
  endif()

  if (USE_LIBFUZZER)
      if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
          message(FATAL_ERROR "Use Clang for libfuzzer")
      endif()
      target_compile_options(${BPFTRACE} PUBLIC "-DLIBFUZZER")
      message(STATUS "Use libfuzzer")
  endif()
endif()

# compile definitions

if (KERNEL_HEADERS_DIR)
  MESSAGE(STATUS "Using KERNEL_HEADERS_DIR=${KERNEL_HEADERS_DIR}")
endif()
target_compile_definitions(runtime PUBLIC KERNEL_HEADERS_DIR="${KERNEL_HEADERS_DIR}")

if (NOT SYSTEM_INCLUDE_PATHS EQUAL "auto")
  MESSAGE(STATUS "Using SYSTEM_INCLUDE_PATHS=${SYSTEM_INCLUDE_PATHS}")
endif()
target_compile_definitions(runtime PUBLIC SYSTEM_INCLUDE_PATHS="${SYSTEM_INCLUDE_PATHS}")

# This is run on every build to ensure the version string is always up-to-date
add_custom_target(version_h
  COMMAND ${CMAKE_COMMAND}
    -DVERSION_H_IN=${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
    -DVERSION_H=${CMAKE_CURRENT_BINARY_DIR}/version.h
    -Dbpftrace_VERSION_MAJOR=${bpftrace_VERSION_MAJOR}
    -Dbpftrace_VERSION_MINOR=${bpftrace_VERSION_MINOR}
    -Dbpftrace_VERSION_PATCH=${bpftrace_VERSION_PATCH}
    -P ${CMAKE_SOURCE_DIR}/cmake/Version.cmake
)
add_dependencies(${BPFTRACE} version_h)
add_dependencies(libbpftrace version_h)

target_include_directories(required_resources PRIVATE ${CMAKE_BINARY_DIR})
target_include_directories(required_resources PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(required_resources PRIVATE ${BPFTRACE_FLAGS})
target_include_directories(runtime PRIVATE ${CMAKE_BINARY_DIR})
target_include_directories(runtime PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(runtime PRIVATE ${BPFTRACE_FLAGS})
target_include_directories(libbpftrace PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_definitions(libbpftrace PRIVATE ${BPFTRACE_FLAGS})

# Linking
if(STATIC_LINKING)
  target_link_options(${BPFTRACE} BEFORE PRIVATE "-static-libgcc" "-static-libstdc++")
endif(STATIC_LINKING)


target_link_libraries(runtime ${LIBBPF_LIBRARIES} ${ZLIB_LIBRARIES})
target_link_libraries(libbpftrace parser resources runtime aot ast arch cxxdemangler_llvm)

if(LLDB_FOUND)
  target_link_libraries(runtime LLDB)
endif(LLDB_FOUND)

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
    if (LIBZSTD_FOUND)
      set_property(TARGET LIBZSTD PROPERTY IMPORTED_LOCATION ${LIBZSTD_LIBRARIES})
      target_link_libraries(runtime LIBZSTD)
    endif(LIBZSTD_FOUND)

    add_library(LIBSFRAME STATIC IMPORTED)
    if (LIBSFRAME_FOUND)
      set_property(TARGET LIBSFRAME PROPERTY IMPORTED_LOCATION ${LIBSFRAME_LIBRARIES})
      target_link_libraries(runtime LIBSFRAME)
    endif()
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

# Support for std::filesystem
# GCC version <9 and Clang (all versions) require -lstdc++fs
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR ${CMAKE_CXX_COMPILER_VERSION} VERSION_LESS "9")
  target_link_libraries(runtime "stdc++fs")
  target_link_libraries(libbpftrace "stdc++fs")
endif()

if (BUILD_ASAN)
  target_compile_options(${BPFTRACE} PUBLIC "-fsanitize=address")
  target_link_options(${BPFTRACE} PUBLIC "-fsanitize=address")
endif()

if (USE_LIBFUZZER)
  if (BUILD_ASAN)
    target_compile_options(${BPFTRACE} PUBLIC "-fsanitize=fuzzer,address")
    target_link_options(${BPFTRACE} PUBLIC "-fsanitize=fuzzer")
  else()
    target_compile_options(${BPFTRACE} PUBLIC "-fsanitize=fuzzer")
    target_link_options(${BPFTRACE} PUBLIC "-fsanitize=fuzzer,address")
  endif()
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

unset(MAIN_SRC)
unset(BPFTRACE)

add_subdirectory(aot)
add_subdirectory(arch)
add_subdirectory(ast)
add_subdirectory(cxxdemangler)
add_subdirectory(resources)
