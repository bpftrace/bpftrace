add_compile_options("-Wno-undef")

# Regenerate codegen_includes.cpp whenever anything in the tests/codegen
# directory changes
file(GLOB_RECURSE CODEGEN_SOURCES codegen/*.cpp codegen/*.h)
add_custom_command(OUTPUT ${CMAKE_BINARY_DIR}/tests/codegen_includes.cpp
  COMMAND
    ${CMAKE_COMMAND}
    -DTEST_SRC_DIR="${CMAKE_SOURCE_DIR}/tests/codegen"
    -P ${CMAKE_SOURCE_DIR}/tests/codegen/generate_codegen_includes.cmake
  DEPENDS ${CODEGEN_SOURCES})

if(${LLVM_VERSION_MAJOR} VERSION_EQUAL 12)
  set(CODEGEN_SRC ${CMAKE_BINARY_DIR}/tests/codegen_includes.cpp)
else()
  set(CODEGEN_SRC "")
  message(STATUS "Disabled codegen test for LLVM != 12")
endif()

add_executable(bpftrace_test
  ast.cpp
  bpfbytecode.cpp
  bpftrace.cpp
  child.cpp
  clang_parser.cpp
  config.cpp
  field_analyser.cpp
  log.cpp
  main.cpp
  mocks.cpp
  parser.cpp
  portability_analyser.cpp
  procmon.cpp
  probe.cpp
  config_analyser.cpp
  resource_analyser.cpp
  required_resources.cpp
  semantic_analyser.cpp
  tracepoint_format_parser.cpp
  utils.cpp

  ${CODEGEN_SRC}
)

add_subdirectory(data)
add_dependencies(bpftrace_test debuginfo_data)
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
  # Ninja build system needs the byproducts set explicitly so it can
  # check for missing dependencies.
  # https://cmake.org/pipermail/cmake/2015-April/060234.html
  set(gtest_byproducts
    <BINARY_DIR>/googlemock/gtest/libgtest.a
    <BINARY_DIR>/googlemock/gtest/libgtest_main.a
    <BINARY_DIR>/googlemock/libgmock.a
  )
  include(ExternalProject)
  ExternalProject_Add(gtest-git
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.11.0
    STEP_TARGETS build update
    EXCLUDE_FROM_ALL 1
    BUILD_BYPRODUCTS ${gtest_byproducts}
  )
  add_dependencies(bpftrace_test gtest-git-build)
  ExternalProject_Get_Property(gtest-git source_dir binary_dir)
  target_include_directories(bpftrace_test PUBLIC ${source_dir}/googletest/include)
  target_include_directories(bpftrace_test PUBLIC ${source_dir}/googlemock/include)
  target_link_libraries(bpftrace_test ${binary_dir}/lib/libgtest.a)
  target_link_libraries(bpftrace_test ${binary_dir}/lib/libgtest_main.a)
  target_link_libraries(bpftrace_test ${binary_dir}/lib/libgmock.a)
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
configure_file(runtime-tests.sh runtime-tests.sh COPYONLY)
add_custom_target(
  runtime_tests
  COMMAND ./runtime-tests.sh
  DEPENDS
    testprogs
    testlibs
    ${CMAKE_BINARY_DIR}/src/bpftrace
)
add_test(NAME runtime_tests COMMAND ./runtime-tests.sh)

file(GLOB_RECURSE runtime_test_files
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  CONFIGURE_DEPENDS
  runtime/*
)
list(REMOVE_ITEM runtime_test_files ${CMAKE_CURRENT_SOURCE_DIR}/runtime/engine/*)

foreach(runtime_test_file ${runtime_test_files})
  add_custom_command(
    OUTPUT
      ${CMAKE_CURRENT_BINARY_DIR}/${runtime_test_file}
    COMMAND ${CMAKE_COMMAND} -E copy
      ${CMAKE_CURRENT_SOURCE_DIR}/${runtime_test_file}
      ${CMAKE_CURRENT_BINARY_DIR}/${runtime_test_file}
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/${runtime_test_file}
  )
endforeach()
add_custom_target(runtime_test_files ALL DEPENDS ${runtime_test_files})
add_dependencies(runtime_tests runtime_test_files)

file(GLOB runtime_engine_files runtime/engine/*)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/runtime/engine)
foreach(runtime_engine_file ${runtime_engine_files})
  configure_file(${runtime_engine_file} ${CMAKE_CURRENT_BINARY_DIR}/runtime/engine/ @ONLY)
endforeach()



configure_file(tools-parsing-test.sh tools-parsing-test.sh COPYONLY)
add_custom_target(tools-parsing-test COMMAND ./tools-parsing-test.sh)
add_test(NAME tools-parsing-test COMMAND ./tools-parsing-test.sh)

if (BUILD_ASAN)
  configure_file(memleak-tests.sh memleak-tests.sh COPYONLY)
  add_custom_target(memleak-test COMMAND ./memleak-tests.sh)
endif()

if(ENABLE_TEST_VALIDATE_CODEGEN)
  if(${LLVM_VERSION_MAJOR} VERSION_EQUAL 12)
    message(STATUS "Adding codegen-validator test")
    configure_file(codegen-validator.sh codegen-validator.sh COPYONLY)
    add_custom_target(codegen-validator COMMAND ./codegen-validator.sh)
    add_test(NAME codegen-validator COMMAND ./codegen-validator.sh ${CMAKE_SOURCE_DIR})
  else()
    message(STATUS "Not building with LLVM 12, skipping codegen-validator test")
  endif()
else()
  message(STATUS "codegen-validator test disabled")
endif()
