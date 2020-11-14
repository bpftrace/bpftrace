if(HAVE_BFD_DISASM)
  set(BFD_DISASM_SRC bfd-disasm.cpp)
endif()

if(BUILD_FUZZ)
  set(MAIN_SRC fuzz_main.cpp)
  set(BPFTRACE bpftrace_fuzz)
else()
  set(MAIN_SRC main.cpp)
  set(BPFTRACE bpftrace)
endif()

add_executable(${BPFTRACE}
  attached_probe.cpp
  bpffeature.cpp
  bpftrace.cpp
  btf.cpp
  child.cpp
  clang_parser.cpp
  disasm.cpp
  driver.cpp
  fake_map.cpp
  list.cpp
  lockdown.cpp
  log.cpp
  map.cpp
  mapkey.cpp
  output.cpp
  procmon.cpp
  printf.cpp
  resolve_cgroupid.cpp
  signal.cpp
  struct.cpp
  tracepoint_format_parser.cpp
  types.cpp
  usdt.cpp
  utils.cpp
  ${BFD_DISASM_SRC}
  ${MAIN_SRC}
)

if(HAVE_NAME_TO_HANDLE_AT)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_NAME_TO_HANDLE_AT=1)
endif(HAVE_NAME_TO_HANDLE_AT)
if(HAVE_BCC_PROG_LOAD)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_BCC_PROG_LOAD)
endif(HAVE_BCC_PROG_LOAD)
if(HAVE_BCC_CREATE_MAP)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_BCC_CREATE_MAP)
endif(HAVE_BCC_CREATE_MAP)
if(HAVE_BCC_ELF_FOREACH_SYM)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_BCC_ELF_FOREACH_SYM)
endif(HAVE_BCC_ELF_FOREACH_SYM)
if(HAVE_BCC_USDT_ADDSEM)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_BCC_USDT_ADDSEM)
endif(HAVE_BCC_USDT_ADDSEM)
if (LIBBPF_BTF_DUMP_FOUND)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_LIBBPF_BTF_DUMP)
  target_include_directories(${BPFTRACE} PUBLIC ${LIBBPF_INCLUDE_DIRS})
  target_link_libraries(${BPFTRACE} ${LIBBPF_LIBRARIES})
  if (HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
    target_compile_definitions(${BPFTRACE} PRIVATE HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
  endif()
endif(LIBBPF_BTF_DUMP_FOUND)
if (LIBBPF_FOUND)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_LIBBPF)
endif(LIBBPF_FOUND)

if (HAVE_LIBBPF_MAP_BATCH)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_LIBBPF_MAP_BATCH)
endif()

if (HAVE_BCC_KFUNC)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_BCC_KFUNC)
endif(HAVE_BCC_KFUNC)
if(HAVE_BFD_DISASM)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_BFD_DISASM)
  if(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
    target_compile_definitions(${BPFTRACE} PRIVATE LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  endif(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  if(STATIC_LINKING)
    add_library(LIBBFD STATIC IMPORTED)
    set_property(TARGET LIBBFD PROPERTY IMPORTED_LOCATION ${LIBBFD_LIBRARIES})
    target_link_libraries(${BPFTRACE} LIBBFD)
    add_library(LIBOPCODES STATIC IMPORTED)
    set_property(TARGET LIBOPCODES PROPERTY IMPORTED_LOCATION ${LIBOPCODES_LIBRARIES})
    target_link_libraries(${BPFTRACE} LIBOPCODES)
    add_library(LIBIBERTY STATIC IMPORTED)
    set_property(TARGET LIBIBERTY PROPERTY IMPORTED_LOCATION ${LIBIBERTY_LIBRARIES})
    target_link_libraries(${BPFTRACE} LIBIBERTY)
  else()
    target_link_libraries(${BPFTRACE} ${LIBBFD_LIBRARIES})
    target_link_libraries(${BPFTRACE} ${LIBOPCODES_LIBRARIES})
  endif(STATIC_LINKING)
endif(HAVE_BFD_DISASM)
if(LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
  target_compile_definitions(${BPFTRACE} PRIVATE LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
endif(LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
if(LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
  target_compile_definitions(${BPFTRACE} PRIVATE LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
endif(LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)

if (ALLOW_UNSAFE_PROBE)
  target_compile_definitions(${BPFTRACE} PRIVATE HAVE_UNSAFE_PROBE)
endif(ALLOW_UNSAFE_PROBE)

target_link_libraries(${BPFTRACE} arch ast parser resources)

target_link_libraries(${BPFTRACE} ${LIBBCC_LIBRARIES})
if(STATIC_LINKING)
  # These are not part of the static libbcc so have to be added separate
  target_link_libraries(${BPFTRACE} ${LIBBCC_BPF_LIBRARY_STATIC})
  target_link_libraries(${BPFTRACE} ${LIBBPF_LIBRARIES})
  target_link_libraries(${BPFTRACE} ${LIBBCC_LOADER_LIBRARY_STATIC})

  add_library(LIBELF STATIC IMPORTED)
  set_property(TARGET LIBELF PROPERTY IMPORTED_LOCATION ${LIBELF_LIBRARIES})
  target_link_libraries(${BPFTRACE} LIBELF)

  if(NOT STATIC_LIBC)
    set_target_properties(${BPFTRACE} PROPERTIES LINK_FLAGS "${EMBEDDED_LINK_FLAGS}")
  endif()
else()
  target_link_libraries(${BPFTRACE} ${LIBELF_LIBRARIES})
endif(STATIC_LINKING)

# Support for std::filesystem
# GCC version <9 and Clang (all versions) require -lstdc++fs
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR ${CMAKE_CXX_COMPILER_VERSION} VERSION_LESS "9")
  target_link_libraries(${BPFTRACE} "stdc++fs")
endif()

if (BUILD_ASAN)
  if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    # target_link_options is supported in CMake 3.13 and newer
    message("Please use CMake 3.13 or newer to enable ASAN")
  endif()
  target_compile_options(${BPFTRACE} PUBLIC "-fsanitize=address")
  target_link_options(${BPFTRACE} PUBLIC "-fsanitize=address")
endif()

install(TARGETS ${BPFTRACE} DESTINATION ${CMAKE_INSTALL_BINDIR})

set(KERNEL_HEADERS_DIR "" CACHE PATH "Hard-code kernel headers directory")
if (KERNEL_HEADERS_DIR)
  MESSAGE(STATUS "Using KERNEL_HEADERS_DIR=${KERNEL_HEADERS_DIR}")
  target_compile_definitions(${BPFTRACE} PUBLIC KERNEL_HEADERS_DIR="${KERNEL_HEADERS_DIR}")
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
