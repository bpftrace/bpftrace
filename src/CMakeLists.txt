if (NOT DYNAMIC_LINKING)
  set(CMAKE_EXE_LINKER_FLAGS "-static")
endif()

add_executable(bpftrace
  attached_probe.cpp
  bpftrace.cpp
  driver.cpp
  fake_map.cpp
  main.cpp
  map.cpp
  mapkey.cpp
  printf.cpp
  types.cpp
)

target_link_libraries(bpftrace arch ast parser)

llvm_map_components_to_libnames(llvm_libs bpfcodegen ipo irreader mcjit)
target_link_libraries(bpftrace ${llvm_libs})

add_dependencies(bpftrace bcc-build)
ExternalProject_Get_Property(bcc source_dir binary_dir)
target_include_directories(bpftrace PUBLIC ${source_dir}/src/cc)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbpf.a)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbcc-loader-static.a)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbcc.a)
target_link_libraries(bpftrace ${LIBELF_LIBRARIES})
