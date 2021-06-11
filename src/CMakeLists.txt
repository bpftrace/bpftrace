if(HAVE_BFD_DISASM)
  set(BFD_DISASM_SRC bfd-disasm.cpp)
endif()

if(BUILD_FUZZ)
  message(STATUS "Build for fuzzing")
  set(MAIN_SRC fuzz_main.cpp)
  set(BPFTRACE bpftrace_fuzz)
else()
  set(MAIN_SRC main.cpp)
  set(BPFTRACE bpftrace)
endif()

add_library(libbpftrace
  attached_probe.cpp
  bpffeature.cpp
  bpforc.cpp
  bpftrace.cpp
  btf.cpp
  build_info.cpp
  child.cpp
  clang_parser.cpp
  disasm.cpp
  driver.cpp
  imap.cpp
  lockdown.cpp
  log.cpp
  map.cpp
  mapkey.cpp
  output.cpp
  probe_matcher.cpp
  procmon.cpp
  printf.cpp
  relocator.cpp
  resolve_cgroupid.cpp
  required_resources.cpp
  struct.cpp
  tracepoint_format_parser.cpp
  types.cpp
  usdt.cpp
  utils.cpp
  ${BFD_DISASM_SRC}
)
# So it's not "liblibbpftrace"
set_target_properties(libbpftrace PROPERTIES PREFIX "")

add_executable(${BPFTRACE}
  ${MAIN_SRC}
)

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

set(KERNEL_HEADERS_DIR "" CACHE PATH "Hard-code kernel headers directory")
if (KERNEL_HEADERS_DIR)
  MESSAGE(STATUS "Using KERNEL_HEADERS_DIR=${KERNEL_HEADERS_DIR}")
  target_compile_definitions(libbpftrace PUBLIC KERNEL_HEADERS_DIR="${KERNEL_HEADERS_DIR}")
endif()

execute_process(
  COMMAND git describe --abbrev=4 --dirty --tags
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE BPFTRACE_VERSION
  ERROR_VARIABLE GIT_DESCRIBE_ERROR
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE retcode
)

# If the build is not done from a git repo, get the version information from
# the version variables in main CMakeLists.txt
if(NOT "${retcode}" STREQUAL "0")
  set(BPFTRACE_VERSION "v${bpftrace_VERSION_MAJOR}.${bpftrace_VERSION_MINOR}.${bpftrace_VERSION_PATCH}")
endif()

add_definitions("-DBPFTRACE_VERSION=\"${BPFTRACE_VERSION}\"")

target_compile_definitions(libbpftrace PRIVATE ${BPFTRACE_FLAGS})

# Linking
if(STATIC_LINKING)
  if(STATIC_LIBC)
    target_link_options(${BPFTRACE} BEFORE PRIVATE "-static")
  else()
    target_link_options(${BPFTRACE} BEFORE PRIVATE "-static-libgcc" "-static-libstdc++")
  endif(STATIC_LIBC)
endif(STATIC_LINKING)


target_link_libraries(libbpftrace parser resources ast arch)

if (LIBBPF_BTF_DUMP_FOUND)
  target_include_directories(libbpftrace PUBLIC ${LIBBPF_INCLUDE_DIRS})
  target_link_libraries(libbpftrace ${LIBBPF_LIBRARIES})
endif(LIBBPF_BTF_DUMP_FOUND)

if(HAVE_BFD_DISASM)
  if(STATIC_LINKING)
    add_library(LIBBFD STATIC IMPORTED)
    set_property(TARGET LIBBFD PROPERTY IMPORTED_LOCATION ${LIBBFD_LIBRARIES})
    target_link_libraries(libbpftrace LIBBFD)
    add_library(LIBOPCODES STATIC IMPORTED)
    set_property(TARGET LIBOPCODES PROPERTY IMPORTED_LOCATION ${LIBOPCODES_LIBRARIES})
    target_link_libraries(libbpftrace LIBOPCODES)
    add_library(LIBIBERTY STATIC IMPORTED)
    set_property(TARGET LIBIBERTY PROPERTY IMPORTED_LOCATION ${LIBIBERTY_LIBRARIES})
    target_link_libraries(libbpftrace LIBIBERTY)
  else()
    target_link_libraries(libbpftrace ${LIBBFD_LIBRARIES})
    target_link_libraries(libbpftrace ${LIBOPCODES_LIBRARIES})
  endif(STATIC_LINKING)
endif(HAVE_BFD_DISASM)

target_link_libraries(libbpftrace ${LIBBCC_LIBRARIES})

if(STATIC_LINKING)
  # These are not part of the static libbcc so have to be added separate
  target_link_libraries(libbpftrace ${LIBBCC_BPF_LIBRARY_STATIC})
  target_link_libraries(libbpftrace ${LIBBPF_LIBRARIES})
  target_link_libraries(libbpftrace ${LIBBCC_LOADER_LIBRARY_STATIC})

  add_library(LIBELF STATIC IMPORTED)
  set_property(TARGET LIBELF PROPERTY IMPORTED_LOCATION ${LIBELF_LIBRARIES})
  target_link_libraries(libbpftrace LIBELF)
else()
  target_link_libraries(libbpftrace ${LIBELF_LIBRARIES})
endif(STATIC_LINKING)

# Support for std::filesystem
# GCC version <9 and Clang (all versions) require -lstdc++fs
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR ${CMAKE_CXX_COMPILER_VERSION} VERSION_LESS "9")
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
  target_link_libraries(libbpftrace "-Wl,-Bdynamic" "-lrt" "-lpthread" "-ldl" "-lm")
  target_link_libraries(libbpftrace "-Wl,-Bstatic" "-lz")
endif()

unset(MAIN_SRC)
unset(BPFTRACE)
