add_library(util STATIC
  bpf_funcs.cpp
  bpf_names.cpp
  bpf_progs.cpp
  cgroup.cpp
  cpus.cpp
  elf_parser.cpp
  env.cpp
  exceptions.cpp
  int_parser.cpp
  io.cpp
  kernel.cpp
  math.cpp
  memfd.cpp
  opaque.cpp
  paths.cpp
  result.cpp
  strings.cpp
  symbols.cpp
  system.cpp
  temp.cpp
  time.cpp
  tseries.cpp
  wildcard.cpp
  )

if (KERNEL_HEADERS_DIR)
  MESSAGE(STATUS "Using KERNEL_HEADERS_DIR=${KERNEL_HEADERS_DIR}")
endif()
target_compile_definitions(util PUBLIC KERNEL_HEADERS_DIR="${KERNEL_HEADERS_DIR}")

target_link_libraries(util debugfs ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES})
