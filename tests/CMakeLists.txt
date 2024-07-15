add_compile_options("-Werror=undef")

# Regenerate codegen_includes.cpp whenever anything in the tests/codegen
# directory changes
file(GLOB_RECURSE CODEGEN_SOURCES CONFIGURE_DEPENDS codegen/*.cpp codegen/*.h)
set(CODEGEN_INCLUDES_CPP codegen_includes.cpp)
add_custom_command(
  OUTPUT
    ${CODEGEN_INCLUDES_CPP}
  COMMAND
    ${CMAKE_COMMAND}
    -DCODEGEN_INCLUDES_CPP="${CODEGEN_INCLUDES_CPP}"
    -DCODEGEN_SOURCES="${CODEGEN_SOURCES}"
    -P ${CMAKE_SOURCE_DIR}/tests/codegen/generate_codegen_includes.cmake
  DEPENDS
    ${CODEGEN_SOURCES})

# Codegen tests are based on the IR produced by LLVM 18. The compiler used to
# build bpftrace is also important, as decisions on order of evaluation can
# influence the order of the generated IR.
if(${LLVM_VERSION_MAJOR} VERSION_EQUAL 18 AND ${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
  set(CODEGEN_SRC ${CODEGEN_INCLUDES_CPP})
else()
  set(CODEGEN_SRC "")
  message(STATUS "Disabled codegen tests. Requires GNU/GCC and LLVM 18 (found ${CMAKE_CXX_COMPILER_ID}, LLVM ${LLVM_VERSION_MAJOR})")
endif()

add_executable(bpftrace_test
  ast.cpp
  bpfbytecode.cpp
  bpftrace.cpp
  child.cpp
  clang_parser.cpp
  config.cpp
  collect_nodes.cpp
  cstring_view.cpp
  field_analyser.cpp
  log.cpp
  main.cpp
  mocks.cpp
  output.cpp
  parser.cpp
  portability_analyser.cpp
  procmon.cpp
  probe.cpp
  config_analyser.cpp
  resource_analyser.cpp
  required_resources.cpp
  return_path_analyser.cpp
  semantic_analyser.cpp
  tracepoint_format_parser.cpp
  utils.cpp

  ${CODEGEN_SRC}
)

add_subdirectory(data)
if(${LLDB_FOUND})
  add_dependencies(bpftrace_test debuginfo_dwarf_data)
endif()
add_dependencies(bpftrace_test debuginfo_btf_data)
target_include_directories(bpftrace_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_compile_definitions(bpftrace_test PRIVATE TEST_CODEGEN_LOCATION="${CMAKE_SOURCE_DIR}/tests/codegen/llvm/")
target_link_libraries(bpftrace_test libbpftrace)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
  target_compile_definitions(bpftrace_test PRIVATE ARCH_AARCH64)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ppc64" OR
       CMAKE_SYSTEM_PROCESSOR STREQUAL "ppc64le")
  target_compile_definitions(bpftrace_test PRIVATE ARCH_PPC64)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "s390" OR
       CMAKE_SYSTEM_PROCESSOR STREQUAL "s390x")
  target_compile_definitions(bpftrace_test PRIVATE ARCH_S390)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  target_compile_definitions(bpftrace_test PRIVATE ARCH_X86_64)
endif()

target_compile_definitions(bpftrace_test PRIVATE ${BPFTRACE_FLAGS})

if(BUILD_ASAN)
  target_compile_options(bpftrace_test PUBLIC "-fsanitize=address")
  target_link_options(bpftrace_test PUBLIC "-fsanitize=address")
endif()

# Still need to support vendored gtest/gmock b/c old ubuntu versions (< focal)
# only provide gtest/gmock sources -- no precompiled binaries
if(VENDOR_GTEST)
  include(FetchContent)
  set(FETCHCONTENT_QUIET FALSE)
  FetchContent_Declare(
    gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.11.0
  )
  FetchContent_MakeAvailable(gtest)

  target_include_directories(bpftrace_test PUBLIC ${gtest_SOURCE_DIR}/googletest/include)
  target_include_directories(bpftrace_test PUBLIC ${gtest_SOURCE_DIR}/googlemock/include)
  target_link_libraries(bpftrace_test gtest)
  target_link_libraries(bpftrace_test gmock)
else()
  # bpftrace tests require (at minimum) the vendored version (see above).
  # There's no great way to enforce a minimum version from cmake -- the cmake
  # modules don't respect minimum requested version.
  find_package(GTest REQUIRED)
  find_package(GMock REQUIRED)
  include_directories(SYSTEM ${GTEST_INCLUDE_DIRS} ${GMOCK_INCLUDE_DIRS})
  target_link_libraries(bpftrace_test ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARIES})
endif(VENDOR_GTEST)
add_test(NAME bpftrace_test COMMAND bpftrace_test)
if(NOT STATIC_LINKING)
  find_package(Threads REQUIRED)
  target_link_libraries(bpftrace_test ${CMAKE_THREAD_LIBS_INIT})
endif(NOT STATIC_LINKING)

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
add_test(NAME runtime_tests COMMAND ./runtime-tests.sh)

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
add_test(NAME tools-parsing-test COMMAND ./tools-parsing-test.sh)

if (BUILD_ASAN)
  configure_file(memleak-tests.sh memleak-tests.sh COPYONLY)
  add_custom_target(memleak-test COMMAND ./memleak-tests.sh)
endif()

if(ENABLE_TEST_VALIDATE_CODEGEN)
  if(${LLVM_VERSION_MAJOR} VERSION_EQUAL 18)
    message(STATUS "Adding codegen-validator test")
    configure_file(codegen-validator.sh codegen-validator.sh COPYONLY)
    add_custom_target(codegen-validator COMMAND ./codegen-validator.sh)
    add_test(NAME codegen-validator COMMAND ./codegen-validator.sh ${CMAKE_SOURCE_DIR})
  else()
    message(STATUS "Not building with LLVM 18, skipping codegen-validator test")
  endif()
else()
  message(STATUS "codegen-validator test disabled")
endif()
