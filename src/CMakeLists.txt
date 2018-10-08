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
  tracepoint_format_parser.cpp
  types.cpp
  list.cpp
)

target_link_libraries(bpftrace arch ast parser resources)

ExternalProject_Get_Property(bcc source_dir binary_dir)
target_include_directories(bpftrace PUBLIC ${source_dir}/src/cc)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbpf.a)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbcc-loader-static.a)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbcc.a)
target_link_libraries(bpftrace ${binary_dir}/src/cc/frontends/clang/libclang_frontend.a)
target_link_libraries(bpftrace ${LIBELF_LIBRARIES})

install(TARGETS bpftrace DESTINATION bin)
