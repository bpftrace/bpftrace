add_compile_options("-Werror=undef")

add_executable(bpftrace_test
  arch.cpp
  async_action.cpp
  bpfbytecode.cpp
  bpftrace.cpp
  btf.cpp
  child.cpp
  clang_parser.cpp
  named_param.cpp
  config.cpp
  collect_nodes.cpp
  deprecated.cpp
  field_analyser.cpp
  fold_literals.cpp
  function_registry.cpp
  globalvars.cpp
  imports.cpp
  location.cpp
  log.cpp
  macro_expansion.cpp
  main.cpp
  memfd.cpp
  mocks.cpp
  opaque.cpp
  output.cpp
  parser.cpp
  portability_analyser.cpp
  probe_expansion.cpp
  procmon.cpp
  probe.cpp
  config_analyser.cpp
  pass_manager.cpp
  pid_filter_pass.cpp
  recursion_check.cpp
  resource_analyser.cpp
  result.cpp
  required_resources.cpp
  return_path_analyser.cpp
  scopeguard.cpp
  semantic_analyser.cpp
  temp.cpp
  tracepoint_format_parser.cpp
  types.cpp
  type_system.cpp
  unstable_feature.cpp
  utils.cpp
)
add_test(NAME bpftrace_test COMMAND bpftrace_test)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/near_self_file "near_self_file")

add_subdirectory(data)
add_dependencies(bpftrace_test data_source_dwarf data_source_btf data_source_funcs parser)
target_include_directories(bpftrace_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(bpftrace_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(bpftrace_test PRIVATE TEST_CODEGEN_LOCATION="${CMAKE_SOURCE_DIR}/tests/codegen/llvm/")
target_link_libraries(bpftrace_test libbpftrace)
target_link_libraries(bpftrace_test btf)

target_compile_definitions(bpftrace_test PRIVATE ${BPFTRACE_FLAGS})

if(BUILD_ASAN)
  target_compile_options(bpftrace_test PUBLIC "-fsanitize=address")
  target_link_options(bpftrace_test PUBLIC "-fsanitize=address")
endif()

# bpftrace tests require (at minimum) version 1.11.
# There's no great way to enforce a minimum version from cmake -- the cmake
# modules don't respect minimum requested version.
find_package(GTest REQUIRED)
find_package(GMock REQUIRED)
include_directories(SYSTEM ${GTEST_INCLUDE_DIRS} ${GMOCK_INCLUDE_DIRS})
target_link_libraries(bpftrace_test ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARIES})

find_package(Threads REQUIRED)
target_link_libraries(bpftrace_test ${CMAKE_THREAD_LIBS_INIT})

add_subdirectory(testprogs)
add_subdirectory(testlibs)


#
# Runtime Tests
#
configure_file(runtime-tests.sh runtime-tests.sh @ONLY)
add_custom_target(
  runtime_tests
  COMMAND ./runtime-tests.sh
  DEPENDS
    testprogs
    testlibs
    ${CMAKE_BINARY_DIR}/src/bpftrace
)

file(GLOB_RECURSE runtime_test_src_files
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  CONFIGURE_DEPENDS
  runtime/*
)
list(REMOVE_ITEM runtime_test_src_files runtime/engine/cmake_vars.py)

set(runtime_test_files)
foreach(runtime_test_file ${runtime_test_src_files})
  add_custom_command(
    OUTPUT
      ${CMAKE_CURRENT_BINARY_DIR}/${runtime_test_file}
    COMMAND ${CMAKE_COMMAND} -E copy
      ${CMAKE_CURRENT_SOURCE_DIR}/${runtime_test_file}
      ${CMAKE_CURRENT_BINARY_DIR}/${runtime_test_file}
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/${runtime_test_file}
  )
  list(APPEND
    runtime_test_files
    ${CMAKE_CURRENT_BINARY_DIR}/${runtime_test_file}
  )
endforeach()
add_custom_target(runtime_test_files ALL DEPENDS ${runtime_test_files})
add_dependencies(runtime_tests runtime_test_files)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/runtime/engine)
configure_file(runtime/engine/cmake_vars.py ${CMAKE_CURRENT_BINARY_DIR}/runtime/engine/ @ONLY)



configure_file(tools-parsing-test.sh tools-parsing-test.sh COPYONLY)
add_custom_target(tools-parsing-test COMMAND ./tools-parsing-test.sh)
