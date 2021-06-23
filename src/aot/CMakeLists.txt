add_library(aot aot.cpp)
target_include_directories(aot PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_include_directories(aot PUBLIC ${CMAKE_BINARY_DIR})
target_compile_definitions(aot PRIVATE ${BPFTRACE_FLAGS})
