add_compile_options("-Wno-undef")

if (STATIC_LIBC)
  # STATIC_LIBC will set linker flags to -static. We don't want this for
  # testprogs linking, so we clear the flags.
  unset(CMAKE_EXE_LINKER_FLAGS)
endif()

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
  bpftrace.cpp
  child.cpp
  clang_parser.cpp
  log.cpp
  main.cpp
  mocks.cpp
  parser.cpp
  portability_analyser.cpp
  procmon.cpp
  probe.cpp
  required_resources.cpp
  semantic_analyser.cpp
  tracepoint_format_parser.cpp
  utils.cpp

  ${CODEGEN_SRC}
)

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

if(STATIC_LINKING)
  if(EMBED_USE_LLVM)
    target_link_options(bpftrace_test BEFORE PRIVATE "-static-libgcc" "-static-libstdc++")
  endif()
  if(STATIC_LIBC)
    set_target_properties(bpftrace_test PROPERTIES LINK_FLAGS "-static")
  endif()
endif(STATIC_LINKING)

# Still need to support vendored gtest/gmock b/c old ubuntu versions (< focal)
# only provide gtest/gmock sources -- no precompiled binaries
if(VENDOR_GTEST)
  # Ninja build system needs the byproducts set explicilty so it can
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
    GIT_TAG release-1.10.0
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

# Compile all testprograms, one per .c file for runtime testing
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/testprogs/)
file(GLOB testprogs testprogs/*.c)
set(compiled_testprogs "")
foreach(testprog ${testprogs})
  get_filename_component(bin_name ${testprog} NAME_WE)
  add_executable (${bin_name} ${testprog})
  if(HAVE_SYSTEMTAP_SYS_SDT_H)
    target_compile_definitions(${bin_name} PRIVATE HAVE_SYSTEMTAP_SYS_SDT_H)
  endif(HAVE_SYSTEMTAP_SYS_SDT_H)
  set_target_properties(${bin_name} PROPERTIES LINK_SEARCH_START_STATIC FALSE LINK_SEARCH_END_STATIC FALSE RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/testprogs/ COMPILE_FLAGS "-g -O0" LINK_FLAGS "-no-pie")
  list(APPEND compiled_testprogs ${CMAKE_CURRENT_BINARY_DIR}/testprogs/${bin_name})
endforeach()
add_custom_target(testprogs DEPENDS ${compiled_testprogs})

target_include_directories(usdt_lib PUBLIC ${CMAKE_SOURCE_DIR}/tests/testlibs/)
target_compile_options(usdt_lib PRIVATE -fPIC)
target_link_libraries(usdt_lib usdt_tp)

# Similarly compile all test libs
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/testlibs/)
file(GLOB testlibs testlibs/*.c)
set(compiled_testlibs "")
foreach(testlib_source ${testlibs})
  get_filename_component(testlib_name ${testlib_source} NAME_WE)
  add_library(${testlib_name} SHARED ${testlib_source})
  set_target_properties(${testlib_name} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/testlibs/ COMPILE_FLAGS "-g -O0")
  if(HAVE_SYSTEMTAP_SYS_SDT_H)
    target_compile_definitions(${testlib_name} PRIVATE HAVE_SYSTEMTAP_SYS_SDT_H)
  endif(HAVE_SYSTEMTAP_SYS_SDT_H)
  # clear the executable bit
  add_custom_command(TARGET ${testlib_name}
    POST_BUILD
    COMMAND chmod -x ${CMAKE_CURRENT_BINARY_DIR}/testlibs/lib${testlib_name}.so)
  list(APPEND compiled_testlibs ${CMAKE_CURRENT_BINARY_DIR}/testlibs/lib${testlib_name}.so)
endforeach()
add_custom_target(testlibs DEPENDS ${compiled_testlibs})

configure_file(runtime-tests.sh runtime-tests.sh COPYONLY)
file(GLOB runtime_tests runtime/*)
list(REMOVE_ITEM runtime_tests ${CMAKE_CURRENT_SOURCE_DIR}/runtime/engine)
list(REMOVE_ITEM runtime_tests ${CMAKE_CURRENT_SOURCE_DIR}/runtime/scripts)
list(REMOVE_ITEM runtime_tests ${CMAKE_CURRENT_SOURCE_DIR}/runtime/outputs)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/runtime/)
foreach(runtime_test ${runtime_tests})
  configure_file(${runtime_test} ${CMAKE_CURRENT_BINARY_DIR}/runtime/ COPYONLY)
endforeach()
file(GLOB runtime_engine_files runtime/engine/*)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/runtime/engine)
foreach(runtime_engine_file ${runtime_engine_files})
  configure_file(${runtime_engine_file} ${CMAKE_CURRENT_BINARY_DIR}/runtime/engine/ COPYONLY)
endforeach()
file(GLOB runtime_test_scripts runtime/scripts/*)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/runtime/scripts)
foreach(runtime_test_script ${runtime_test_scripts})
  configure_file(${runtime_test_script} ${CMAKE_CURRENT_BINARY_DIR}/runtime/scripts/ COPYONLY)
endforeach()
file(GLOB runtime_test_outputs runtime/outputs/*)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/runtime/outputs)
foreach(runtime_test_output ${runtime_test_outputs})
  configure_file(${runtime_test_output} ${CMAKE_CURRENT_BINARY_DIR}/runtime/outputs/ COPYONLY)
endforeach()
add_custom_target(
  runtime-tests
  COMMAND ./runtime-tests.sh
  DEPENDS ${compiled_testprogs} ${compiled_testlibs} ${CMAKE_BINARY_DIR}/src/bpftrace
)
add_test(NAME runtime_test COMMAND ./runtime-tests.sh)

configure_file(tools-parsing-test.sh tools-parsing-test.sh COPYONLY)
add_custom_target(tools-parsing-test COMMAND ./tools-parsing-test.sh)
add_test(NAME tools-parsing-test COMMAND ./tools-parsing-test.sh)

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
