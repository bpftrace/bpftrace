add_library(util STATIC
  bpf_names.cpp
  cgroup.cpp
  cpus.cpp
  env.cpp
  exceptions.cpp
  format.cpp
  int_parser.cpp
  io.cpp
  kernel.cpp
  math.cpp
  paths.cpp
  result.cpp
  symbols.cpp
  system.cpp
  wildcard.cpp
  )

if (KERNEL_HEADERS_DIR)
  MESSAGE(STATUS "Using KERNEL_HEADERS_DIR=${KERNEL_HEADERS_DIR}")
endif()
target_compile_definitions(util PUBLIC KERNEL_HEADERS_DIR="${KERNEL_HEADERS_DIR}")

target_link_libraries(util debugfs)
