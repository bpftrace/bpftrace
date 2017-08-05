find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

set(DYNAMIC_LINKING OFF CACHE BOOL "Build bpftrace as a dynamically linked executable")
if (NOT DYNAMIC_LINKING)
  set(CMAKE_EXE_LINKER_FLAGS "-static")
endif()

add_executable(bpftrace
  ast.cpp
  attached_probe.cpp
  bpftrace.cpp
  codegen_llvm.cpp
  driver.cpp
  irbuilderbpf.cpp
  main.cpp
  map.cpp
  mapkey.cpp
  printer.cpp
  printf.cpp
  semantic_analyser.cpp
  types.cpp
)

target_link_libraries(bpftrace arch parser)

llvm_map_components_to_libnames(llvm_libs bpfcodegen ipo irreader mcjit)
target_link_libraries(bpftrace ${llvm_libs})

add_dependencies(bpftrace bcc-build)
ExternalProject_Get_Property(bcc source_dir binary_dir)
include_directories(${source_dir}/src/cc)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbpf.a)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbcc-loader-static.a)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbcc.a)
target_link_libraries(bpftrace ${LIBELF_LIBRARIES})
