add_compile_options("-Wno-undef")
add_compile_options("-Wno-switch-default")
add_compile_options("-Wno-switch-enum")

include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_BINARY_DIR}/src)

add_executable(bpftrace_test
  main.cpp
  parser.cpp
  semantic_analyser.cpp
  ${CMAKE_SOURCE_DIR}/src/ast.cpp
  ${CMAKE_SOURCE_DIR}/src/attached_probe.cpp
  ${CMAKE_SOURCE_DIR}/src/bpftrace.cpp
  ${CMAKE_SOURCE_DIR}/src/driver.cpp
  ${CMAKE_SOURCE_DIR}/src/map.cpp
  ${CMAKE_SOURCE_DIR}/src/mapkey.cpp
  ${CMAKE_SOURCE_DIR}/src/printer.cpp
  ${CMAKE_SOURCE_DIR}/src/printf.cpp
  ${CMAKE_SOURCE_DIR}/src/semantic_analyser.cpp
  ${CMAKE_SOURCE_DIR}/src/types.cpp
)

target_link_libraries(bpftrace_test arch parser)

add_dependencies(bpftrace_test bcc-build)
ExternalProject_Get_Property(bcc source_dir binary_dir)
include_directories(${source_dir}/src/cc)
target_link_libraries(bpftrace_test ${binary_dir}/src/cc/libbpf.a)
target_link_libraries(bpftrace_test ${binary_dir}/src/cc/libbcc-loader-static.a)
target_link_libraries(bpftrace_test ${binary_dir}/src/cc/libbcc.a)
target_link_libraries(bpftrace_test ${LIBELF_LIBRARIES})

find_package(Threads REQUIRED)

include(ExternalProject)
ExternalProject_Add(gtest
  GIT_REPOSITORY https://github.com/google/googletest.git
  STEP_TARGETS build update
  EXCLUDE_FROM_ALL 1
  UPDATE_DISCONNECTED 1
)
add_dependencies(bpftrace_test gtest-build)
ExternalProject_Get_Property(gtest source_dir binary_dir)
include_directories(${source_dir}/googletest/include)
include_directories(${source_dir}/googlemock/include)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest_main.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/libgmock.a)
target_link_libraries(bpftrace_test ${CMAKE_THREAD_LIBS_INIT})

add_test(NAME bpftrace_test COMMAND bpftrace_test)
