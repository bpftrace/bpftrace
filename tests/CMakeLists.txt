add_compile_options("-Wno-undef")
add_compile_options("-Wno-switch-default")
add_compile_options("-Wno-switch-enum")

add_executable(bpftrace_test
  ast.cpp
  bpftrace.cpp
  clang_parser.cpp
  codegen.cpp
  main.cpp
  parser.cpp
  semantic_analyser.cpp
  tracepoint_format_parser.cpp
  utils.cpp
  ${CMAKE_SOURCE_DIR}/src/attached_probe.cpp
  ${CMAKE_SOURCE_DIR}/src/bpftrace.cpp
  ${CMAKE_SOURCE_DIR}/src/clang_parser.cpp
  ${CMAKE_SOURCE_DIR}/src/driver.cpp
  ${CMAKE_SOURCE_DIR}/src/fake_map.cpp
  ${CMAKE_SOURCE_DIR}/src/map.cpp
  ${CMAKE_SOURCE_DIR}/src/mapkey.cpp
  ${CMAKE_SOURCE_DIR}/src/printf.cpp
  ${CMAKE_SOURCE_DIR}/src/tracepoint_format_parser.cpp
  ${CMAKE_SOURCE_DIR}/src/types.cpp
)

target_link_libraries(bpftrace_test arch ast parser resources)

ExternalProject_Get_Property(bcc source_dir binary_dir)
target_include_directories(bpftrace_test PUBLIC ${source_dir}/src/cc)
target_link_libraries(bpftrace_test ${binary_dir}/src/cc/libbpf.a)
target_link_libraries(bpftrace_test ${binary_dir}/src/cc/libbcc-loader-static.a)
target_link_libraries(bpftrace_test ${binary_dir}/src/cc/libbcc.a)
target_link_libraries(bpftrace_test ${LIBELF_LIBRARIES})

find_package(Threads REQUIRED)

if (OFFLINE_BUILDS)
  include(ExternalProject)
  ExternalProject_Add(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    STEP_TARGETS build update
    EXCLUDE_FROM_ALL 1
    UPDATE_DISCONNECTED 1
    )
else()
  include(ExternalProject)
  ExternalProject_Add(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    STEP_TARGETS build update
    EXCLUDE_FROM_ALL 1
    )
endif()
add_dependencies(bpftrace_test gtest-build)
ExternalProject_Get_Property(gtest source_dir binary_dir)
target_include_directories(bpftrace_test PUBLIC ${source_dir}/googletest/include)
target_include_directories(bpftrace_test PUBLIC ${source_dir}/googlemock/include)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest_main.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/libgmock.a)
target_link_libraries(bpftrace_test ${CMAKE_THREAD_LIBS_INIT})

add_test(NAME bpftrace_test COMMAND bpftrace_test)
