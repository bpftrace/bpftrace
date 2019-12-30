if(HAVE_BFD_DISASM)
  set(BFD_DISASM_SRC bfd-disasm.cpp)
endif()

add_executable(bpftrace
  attached_probe.cpp
  bpftrace.cpp
  btf.cpp
  clang_parser.cpp
  disasm.cpp
  driver.cpp
  fake_map.cpp
  list.cpp
  main.cpp
  map.cpp
  mapkey.cpp
  output.cpp
  printf.cpp
  resolve_cgroupid.cpp
  signal.cpp
  struct.cpp
  tracepoint_format_parser.cpp
  types.cpp
  utils.cpp
  ${BFD_DISASM_SRC}
)

if(HAVE_NAME_TO_HANDLE_AT)
  target_compile_definitions(bpftrace PRIVATE HAVE_NAME_TO_HANDLE_AT=1)
endif(HAVE_NAME_TO_HANDLE_AT)
if(HAVE_BCC_PROG_LOAD)
  target_compile_definitions(bpftrace PRIVATE HAVE_BCC_PROG_LOAD)
endif(HAVE_BCC_PROG_LOAD)
if(HAVE_BCC_CREATE_MAP)
  target_compile_definitions(bpftrace PRIVATE HAVE_BCC_CREATE_MAP)
endif(HAVE_BCC_CREATE_MAP)
if(HAVE_BCC_ELF_FOREACH_SYM)
  target_compile_definitions(bpftrace PRIVATE HAVE_BCC_ELF_FOREACH_SYM)
endif(HAVE_BCC_ELF_FOREACH_SYM)
if(HAVE_GET_CURRENT_CGROUP_ID)
  target_compile_definitions(bpftrace PRIVATE HAVE_GET_CURRENT_CGROUP_ID)
endif(HAVE_GET_CURRENT_CGROUP_ID)
if(HAVE_SEND_SIGNAL)
  target_compile_definitions(bpftrace PRIVATE HAVE_SEND_SIGNAL)
endif(HAVE_SEND_SIGNAL)
if (LIBBPF_BTF_DUMP_FOUND)
  target_compile_definitions(bpftrace PRIVATE HAVE_LIBBPF_BTF_DUMP)
  target_include_directories(bpftrace PUBLIC ${LIBBPF_INCLUDE_DIRS})
  target_link_libraries(bpftrace ${LIBBPF_LIBRARIES})
endif(LIBBPF_BTF_DUMP_FOUND)
if(HAVE_BFD_DISASM)
  target_compile_definitions(bpftrace PRIVATE HAVE_BFD_DISASM)
  if(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
    target_compile_definitions(bpftrace PRIVATE LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  endif(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  target_link_libraries(bpftrace ${LIBBFD_LIBRARIES})
  target_link_libraries(bpftrace ${LIBOPCODES_LIBRARIES})
  if(STATIC_LINKING)
    target_link_libraries(bpftrace ${LIBIBERTY_LIBRARIES})
  endif(STATIC_LINKING)
endif(HAVE_BFD_DISASM)

if (ALLOW_UNSAFE_UPROBE)
  target_compile_definitions(bpftrace PRIVATE HAVE_UNSAFE_UPROBE)
endif(ALLOW_UNSAFE_UPROBE)

target_link_libraries(bpftrace arch ast parser resources)

if (STATIC_LINKING)
  target_link_libraries(bpftrace ${LIBBCC_LIBRARIES})
  target_link_libraries(bpftrace ${LIBBPF_LIBRARY_STATIC})
  target_link_libraries(bpftrace ${LIBBCC_LOADER_LIBRARY_STATIC})
else()
  target_link_libraries(bpftrace ${LIBBCC_LIBRARIES})
endif()
target_link_libraries(bpftrace ${LIBELF_LIBRARIES})

install(TARGETS bpftrace DESTINATION bin)

set(KERNEL_HEADERS_DIR "" CACHE PATH "Hard-code kernel headers directory")
if (KERNEL_HEADERS_DIR)
MESSAGE(STATUS "Using KERNEL_HEADERS_DIR=${KERNEL_HEADERS_DIR}")
target_compile_definitions(bpftrace PUBLIC KERNEL_HEADERS_DIR="${KERNEL_HEADERS_DIR}")
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
