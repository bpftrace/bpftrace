add_library(aot STATIC aot.cpp)
add_dependencies(aot version_h)
target_link_libraries(aot required_resources parser)
target_compile_definitions(aot PRIVATE ${BPFTRACE_FLAGS})

if(STATIC_LINKING)
  target_link_libraries(aot LIBELF)
else()
  target_link_libraries(aot ${LIBELF_LIBRARIES})
endif(STATIC_LINKING)

# Only build aotrt if supported bcc is used
# (https://github.com/iovisor/bcc/commit/719191867a25ce07dc96f7faf9b8ccedadc7ec44)
if(NOT LIBBCC_BPF_CONTAINS_RUNTIME)
  return()
endif()

add_executable(bpftrace-aotrt aot_main.cpp)
target_compile_definitions(bpftrace-aotrt PRIVATE ${BPFTRACE_FLAGS})
target_link_libraries(bpftrace-aotrt aot runtime arch ast ast_defs util cxxdemangler_stdlib)
install(TARGETS bpftrace-aotrt DESTINATION ${CMAKE_INSTALL_BINDIR})

if(LIBPCAP_FOUND)
  target_link_libraries(bpftrace-aotrt ${LIBPCAP_LIBRARIES})
endif(LIBPCAP_FOUND)

# Linking
target_link_options(bpftrace-aotrt BEFORE PRIVATE
  $<$<BOOL:${STATIC_LINKING}>:-static-libgcc>
  $<$<BOOL:${STATIC_LINKING}>:-static-libstdc++>
)

# ASAN/UBSAN
target_link_options(bpftrace-aotrt PUBLIC
  $<$<BOOL:${BUILD_ASAN}>:-fsanitize=address>
  $<$<BOOL:${BUILD_UBSAN}>:-fsanitize=undefined>
)
