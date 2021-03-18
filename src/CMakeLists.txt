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
  child.cpp
  clang_parser.cpp
  disasm.cpp
  driver.cpp
  lockdown.cpp
  log.cpp
  map.cpp
  mapkey.cpp
  output.cpp
  probe_matcher.cpp
  procmon.cpp
  printf.cpp
  resolve_cgroupid.cpp
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

if(HAVE_NAME_TO_HANDLE_AT)
  target_compile_definitions(libbpftrace PRIVATE HAVE_NAME_TO_HANDLE_AT=1)
endif(HAVE_NAME_TO_HANDLE_AT)
if(HAVE_BCC_PROG_LOAD)
  target_compile_definitions(libbpftrace PRIVATE HAVE_BCC_PROG_LOAD)
endif(HAVE_BCC_PROG_LOAD)
if(HAVE_BCC_CREATE_MAP)
  target_compile_definitions(libbpftrace PRIVATE HAVE_BCC_CREATE_MAP)
endif(HAVE_BCC_CREATE_MAP)
if(HAVE_BCC_ELF_FOREACH_SYM)
  target_compile_definitions(libbpftrace PRIVATE HAVE_BCC_ELF_FOREACH_SYM)
endif(HAVE_BCC_ELF_FOREACH_SYM)
if(HAVE_BCC_USDT_ADDSEM)
  target_compile_definitions(libbpftrace PRIVATE HAVE_BCC_USDT_ADDSEM)
endif(HAVE_BCC_USDT_ADDSEM)
if (LIBBPF_BTF_DUMP_FOUND)
  target_compile_definitions(libbpftrace PRIVATE HAVE_LIBBPF_BTF_DUMP)
  target_include_directories(${BPFTRACE} PUBLIC ${LIBBPF_INCLUDE_DIRS})
  target_link_libraries(libbpftrace ${LIBBPF_LIBRARIES})
  if (HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
    target_compile_definitions(libbpftrace PRIVATE HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
  endif()
endif(LIBBPF_BTF_DUMP_FOUND)
if (LIBBPF_FOUND)
  target_compile_definitions(libbpftrace PRIVATE HAVE_LIBBPF)
endif(LIBBPF_FOUND)

if (HAVE_LIBBPF_MAP_BATCH)
  target_compile_definitions(libbpftrace PRIVATE HAVE_LIBBPF_MAP_BATCH)
endif()

if (HAVE_BCC_KFUNC)
  target_compile_definitions(libbpftrace PRIVATE HAVE_BCC_KFUNC)
endif(HAVE_BCC_KFUNC)
if(HAVE_BFD_DISASM)
  target_compile_definitions(libbpftrace PRIVATE HAVE_BFD_DISASM)
  if(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
    target_compile_definitions(libbpftrace PRIVATE LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  endif(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
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
if(LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
  target_compile_definitions(libbpftrace PRIVATE LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
endif(LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
if(LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
  target_compile_definitions(libbpftrace PRIVATE LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
endif(LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)

if (ALLOW_UNSAFE_PROBE)
  target_compile_definitions(libbpftrace PRIVATE HAVE_UNSAFE_PROBE)
endif(ALLOW_UNSAFE_PROBE)

target_link_libraries(libbpftrace arch ast parser resources)

target_link_libraries(libbpftrace ${LIBBCC_LIBRARIES})
if(STATIC_LINKING)
  # These are not part of the static libbcc so have to be added separate
  target_link_libraries(libbpftrace ${LIBBCC_BPF_LIBRARY_STATIC})
  target_link_libraries(libbpftrace ${LIBBPF_LIBRARIES})
  target_link_libraries(libbpftrace ${LIBBCC_LOADER_LIBRARY_STATIC})

  add_library(LIBELF STATIC IMPORTED)
  set_property(TARGET LIBELF PROPERTY IMPORTED_LOCATION ${LIBELF_LIBRARIES})
  target_link_libraries(libbpftrace LIBELF)

  if(NOT STATIC_LIBC)
    set_target_properties(${BPFTRACE} PROPERTIES LINK_FLAGS "${EMBEDDED_LINK_FLAGS}")
  endif()
else()
  target_link_libraries(libbpftrace ${LIBELF_LIBRARIES})
endif(STATIC_LINKING)

# Support for std::filesystem
# GCC version <9 and Clang (all versions) require -lstdc++fs
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR ${CMAKE_CXX_COMPILER_VERSION} VERSION_LESS "9")
  target_link_libraries(libbpftrace "stdc++fs")
endif()

if (BUILD_ASAN)
  if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    # target_link_options is supported in CMake 3.13 and newer
    message("Please use CMake 3.13 or newer to enable ASAN")
  endif()
  target_compile_options(${BPFTRACE} PUBLIC "-fsanitize=address")
  target_link_options(${BPFTRACE} PUBLIC "-fsanitize=address")
endif()

if (USE_LIBFUZZER)
  if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    message("Please use CMake 3.13 or newer to use libfuzzer")
  endif()
  if (BUILD_ASAN)
    target_compile_options(${BPFTRACE} PUBLIC "-fsanitize=fuzzer,address")
    target_link_options(${BPFTRACE} PUBLIC "-fsanitize=fuzzer")
  else()
      target_compile_options(${BPFTRACE} PUBLIC "-fsanitize=fuzzer")
      target_link_options(${BPFTRACE} PUBLIC "-fsanitize=fuzzer,address")
  endif()
endif()

install(TARGETS ${BPFTRACE} DESTINATION ${CMAKE_INSTALL_BINDIR})

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

unset(MAIN_SRC)
unset(BPFTRACE)
