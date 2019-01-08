add_executable(bpftrace
  attached_probe.cpp
  bpftrace.cpp
  clang_parser.cpp
  driver.cpp
  fake_map.cpp
  main.cpp
  map.cpp
  mapkey.cpp
  printf.cpp
  resolve_cgroupid.cpp
  tracepoint_format_parser.cpp
  types.cpp
  list.cpp
)

if(HAVE_NAME_TO_HANDLE_AT)
  target_compile_definitions(bpftrace PRIVATE HAVE_NAME_TO_HANDLE_AT=1)
endif(HAVE_NAME_TO_HANDLE_AT)
target_link_libraries(bpftrace arch ast parser resources)

target_link_libraries(bpftrace ${LIBBCC_LIBRARIES})
target_link_libraries(bpftrace ${LIBELF_LIBRARIES})

install(TARGETS bpftrace DESTINATION bin)

set(KERNEL_HEADERS_DIR "" CACHE PATH "Hard-code kernel headers directory")
if (KERNEL_HEADERS_DIR)
MESSAGE(STATUS "Using KERNEL_HEADERS_DIR=${KERNEL_HEADERS_DIR}")
target_compile_definitions(bpftrace PUBLIC KERNEL_HEADERS_DIR="${KERNEL_HEADERS_DIR}")
endif()
