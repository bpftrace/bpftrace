add_compile_options("-Wno-undef")
add_compile_options("-Wno-switch-default")
add_compile_options("-Wno-switch-enum")

add_executable(bpftrace_test parser.cpp)

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
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest_main.a)
target_link_libraries(bpftrace_test ${CMAKE_THREAD_LIBS_INIT})

add_test(NAME bpftrace_test COMMAND bpftrace_test)
