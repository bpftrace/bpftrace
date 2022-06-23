add_library(aot aot.cpp)
add_dependencies(aot parser)
target_include_directories(aot PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_include_directories(aot PUBLIC ${CMAKE_BINARY_DIR})
target_compile_definitions(aot PRIVATE ${BPFTRACE_FLAGS})

# Only build aotrt if supported bcc is used
# (https://github.com/iovisor/bcc/commit/719191867a25ce07dc96f7faf9b8ccedadc7ec44)
if(NOT LIBBCC_BPF_CONTAINS_RUNTIME)
  return()
endif()

add_executable(bpftrace-aotrt aot_main.cpp)
target_link_libraries(bpftrace-aotrt aot runtime arch ast_defs cxxdemangler_stdlib)
install(TARGETS bpftrace-aotrt DESTINATION ${CMAKE_INSTALL_BINDIR})

# Linking
if(STATIC_LINKING)
  if(STATIC_LIBC)
    target_link_options(bpftrace-aotrt BEFORE PRIVATE "-static")
  else()
    target_link_options(bpftrace-aotrt  BEFORE PRIVATE "-static-libgcc" "-static-libstdc++")
  endif(STATIC_LIBC)
endif(STATIC_LINKING)

# ASAN
if(BUILD_ASAN)
  target_compile_options(bpftrace-aotrt PUBLIC "-fsanitize=address")
  target_link_options(bpftrace-aotrt PUBLIC "-fsanitize=address")
endif()
