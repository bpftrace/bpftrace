if (NOT DYNAMIC_LINKING)
  set(CMAKE_EXE_LINKER_FLAGS "-static")
endif()

add_compile_options("-Wno-undef")
add_compile_options("-Wno-switch-default")
add_compile_options("-Wno-switch-enum")

add_executable(bpftrace_test
  ast.cpp
  bpftrace.cpp
  codegen.cpp
  main.cpp
  parser.cpp
  semantic_analyser.cpp
  ${CMAKE_SOURCE_DIR}/src/attached_probe.cpp
  ${CMAKE_SOURCE_DIR}/src/bpftrace.cpp
  ${CMAKE_SOURCE_DIR}/src/driver.cpp
  ${CMAKE_SOURCE_DIR}/src/fake_map.cpp
  ${CMAKE_SOURCE_DIR}/src/map.cpp
  ${CMAKE_SOURCE_DIR}/src/mapkey.cpp
  ${CMAKE_SOURCE_DIR}/src/printf.cpp
  ${CMAKE_SOURCE_DIR}/src/types.cpp
  ${CMAKE_SOURCE_DIR}/src/ast/ast.cpp
  ${CMAKE_SOURCE_DIR}/src/ast/codegen_llvm.cpp
  ${CMAKE_SOURCE_DIR}/src/ast/irbuilderbpf.cpp
  ${CMAKE_SOURCE_DIR}/src/ast/printer.cpp
  ${CMAKE_SOURCE_DIR}/src/ast/semantic_analyser.cpp
)

target_link_libraries(bpftrace_test arch parser)

llvm_map_components_to_libnames(llvm_libs bpfcodegen ipo irreader mcjit)
target_link_libraries(bpftrace_test ${llvm_libs})

add_dependencies(bpftrace_test bcc-build)
ExternalProject_Get_Property(bcc source_dir binary_dir)
target_include_directories(bpftrace_test PUBLIC ${source_dir}/src/cc)
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
target_include_directories(bpftrace_test PUBLIC ${source_dir}/googletest/include)
target_include_directories(bpftrace_test PUBLIC ${source_dir}/googlemock/include)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest_main.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/libgmock.a)
target_link_libraries(bpftrace_test ${CMAKE_THREAD_LIBS_INIT})

add_test(NAME bpftrace_test COMMAND bpftrace_test)
