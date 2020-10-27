add_compile_options("-Wno-undef")
add_compile_options("-Wno-switch-default")
add_compile_options("-Wno-switch-enum")

if(HAVE_BFD_DISASM)
  set(BFD_DISASM_SRC ${CMAKE_SOURCE_DIR}/src/bfd-disasm.cpp)
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

if(${LLVM_VERSION} VERSION_LESS 11.0.0)
  set(CODEGEN_SRC ${CMAKE_BINARY_DIR}/tests/codegen_includes.cpp)
else()
  set(CODEGEN_SRC "")
  message("Disabled codegen test for LLVM >= 11")
endif()

add_executable(bpftrace_test
  ast.cpp
  bpftrace.cpp
  child.cpp
  clang_parser.cpp
  main.cpp
  mocks.cpp
  parser.cpp
  procmon.cpp
  probe.cpp
  semantic_analyser.cpp
  tracepoint_format_parser.cpp
  utils.cpp

  ${CODEGEN_SRC}

  ${CMAKE_SOURCE_DIR}/src/attached_probe.cpp
  ${CMAKE_SOURCE_DIR}/src/bpftrace.cpp
  ${CMAKE_SOURCE_DIR}/src/bpffeature.cpp
  ${CMAKE_SOURCE_DIR}/src/btf.cpp
  ${CMAKE_SOURCE_DIR}/src/child.cpp
  ${CMAKE_SOURCE_DIR}/src/clang_parser.cpp
  ${CMAKE_SOURCE_DIR}/src/disasm.cpp
  ${CMAKE_SOURCE_DIR}/src/driver.cpp
  ${CMAKE_SOURCE_DIR}/src/fake_map.cpp
  ${CMAKE_SOURCE_DIR}/src/map.cpp
  ${CMAKE_SOURCE_DIR}/src/mapkey.cpp
  ${CMAKE_SOURCE_DIR}/src/output.cpp
  ${CMAKE_SOURCE_DIR}/src/printf.cpp
  ${CMAKE_SOURCE_DIR}/src/procmon.cpp
  ${CMAKE_SOURCE_DIR}/src/resolve_cgroupid.cpp
  ${CMAKE_SOURCE_DIR}/src/signal.cpp
  ${CMAKE_SOURCE_DIR}/src/struct.cpp
  ${CMAKE_SOURCE_DIR}/src/tracepoint_format_parser.cpp
  ${CMAKE_SOURCE_DIR}/src/types.cpp
  ${CMAKE_SOURCE_DIR}/src/usdt.cpp
  ${CMAKE_SOURCE_DIR}/src/utils.cpp
  ${BFD_DISASM_SRC}
)

if(HAVE_NAME_TO_HANDLE_AT)
  target_compile_definitions(bpftrace_test PRIVATE HAVE_NAME_TO_HANDLE_AT=1)
endif(HAVE_NAME_TO_HANDLE_AT)
if(HAVE_BCC_PROG_LOAD)
  target_compile_definitions(bpftrace_test PRIVATE HAVE_BCC_PROG_LOAD)
endif(HAVE_BCC_PROG_LOAD)
if(HAVE_BCC_CREATE_MAP)
  target_compile_definitions(bpftrace_test PRIVATE HAVE_BCC_CREATE_MAP)
endif(HAVE_BCC_CREATE_MAP)
if (LIBBPF_BTF_DUMP_FOUND)
  target_compile_definitions(bpftrace_test PRIVATE HAVE_LIBBPF_BTF_DUMP)
  target_include_directories(bpftrace_test PUBLIC ${LIBBPF_INCLUDE_DIRS})
  target_link_libraries(bpftrace_test ${LIBBPF_LIBRARIES})
  if (HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
    target_compile_definitions(bpftrace_test PRIVATE HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
  endif()
endif(LIBBPF_BTF_DUMP_FOUND)
if (HAVE_BCC_KFUNC)
  target_compile_definitions(bpftrace_test PRIVATE HAVE_BCC_KFUNC)
endif(HAVE_BCC_KFUNC)
if(HAVE_BCC_USDT_ADDSEM)
  target_compile_definitions(bpftrace PRIVATE HAVE_BCC_USDT_ADDSEM)
endif(HAVE_BCC_USDT_ADDSEM)
target_compile_definitions(bpftrace_test PRIVATE TEST_CODEGEN_LOCATION="${CMAKE_SOURCE_DIR}/tests/codegen/llvm/")
if(HAVE_BFD_DISASM)
  target_compile_definitions(bpftrace_test PRIVATE HAVE_BFD_DISASM)
  if(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
    target_compile_definitions(bpftrace_test PRIVATE LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  endif(LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
  if(STATIC_LINKING)
    add_library(LIBBFD STATIC IMPORTED)
    set_property(TARGET LIBBFD PROPERTY IMPORTED_LOCATION ${LIBBFD_LIBRARIES})
    target_link_libraries(bpftrace_test LIBBFD)
    add_library(LIBOPCODES STATIC IMPORTED)
    set_property(TARGET LIBOPCODES PROPERTY IMPORTED_LOCATION ${LIBOPCODES_LIBRARIES})
    target_link_libraries(bpftrace_test LIBOPCODES)
    add_library(LIBIBERTY STATIC IMPORTED)
    set_property(TARGET LIBIBERTY PROPERTY IMPORTED_LOCATION ${LIBIBERTY_LIBRARIES})
    target_link_libraries(bpftrace_test LIBIBERTY)
  else()
    target_link_libraries(bpftrace_test ${LIBBFD_LIBRARIES})
    target_link_libraries(bpftrace_test ${LIBOPCODES_LIBRARIES})
  endif(STATIC_LINKING)
endif(HAVE_BFD_DISASM)

target_link_libraries(bpftrace_test arch ast parser resources)

target_link_libraries(bpftrace_test ${LIBBCC_LIBRARIES})
if (STATIC_LINKING)
  if(EMBED_LLVM OR EMBED_CLANG)
    set_target_properties(bpftrace_test PROPERTIES LINK_FLAGS "${EMBEDDED_LINK_FLAGS}")
  endif()

  # These are not part of the static libbcc so have to be added separate
  target_link_libraries(bpftrace_test ${LIBBCC_BPF_LIBRARY_STATIC})
  target_link_libraries(bpftrace_test ${LIBBPF_LIBRARIES})
  target_link_libraries(bpftrace_test ${LIBBCC_LOADER_LIBRARY_STATIC})

  add_library(LIBELF STATIC IMPORTED)
  set_property(TARGET LIBELF PROPERTY IMPORTED_LOCATION ${LIBELF_LIBRARIES})
  target_link_libraries(bpftrace_test LIBELF)
else()
  target_link_libraries(bpftrace_test ${LIBELF_LIBRARIES})
endif(STATIC_LINKING)

find_package(Threads REQUIRED)

# Ninja build system needs the byproducts set explicilty so it can
# check for missing dependencies.
# https://cmake.org/pipermail/cmake/2015-April/060234.html
set(gtest_byproducts
  <BINARY_DIR>/googlemock/gtest/libgtest.a
  <BINARY_DIR>/googlemock/gtest/libgtest_main.a
  <BINARY_DIR>/googlemock/libgmock.a
)
include(ExternalProject)
if (OFFLINE_BUILDS)
  ExternalProject_Add(gtest-git
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.8.1
    STEP_TARGETS build update
    EXCLUDE_FROM_ALL 1
    UPDATE_DISCONNECTED 1
    BUILD_BYPRODUCTS ${gtest_byproducts}
    )
else()
  ExternalProject_Add(gtest-git
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.8.1
    STEP_TARGETS build update
    EXCLUDE_FROM_ALL 1
    BUILD_BYPRODUCTS ${gtest_byproducts}
    )
endif()
add_dependencies(bpftrace_test gtest-git-build)
ExternalProject_Get_Property(gtest-git source_dir binary_dir)
target_include_directories(bpftrace_test PUBLIC ${source_dir}/googletest/include)
target_include_directories(bpftrace_test PUBLIC ${source_dir}/googlemock/include)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest_main.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/libgmock.a)
if(NOT STATIC_LINKING)
  target_link_libraries(bpftrace_test ${CMAKE_THREAD_LIBS_INIT})
endif(NOT STATIC_LINKING)

add_test(NAME bpftrace_test COMMAND bpftrace_test)

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
  set_target_properties( ${bin_name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/testprogs/ COMPILE_FLAGS "-g -O0" LINK_FLAGS "-no-pie")
  list(APPEND compiled_testprogs ${CMAKE_CURRENT_BINARY_DIR}/testprogs/${bin_name})
endforeach()
add_custom_target(testprogs DEPENDS ${compiled_testprogs})

# Similarly compile all test libs
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/testlibs/)
file(GLOB testlibs testlibs/*.c)
set(compiled_testlibs "")
foreach(testlib_source ${testlibs})
  get_filename_component(testlib_name ${testlib_source} NAME_WE)
  add_library(${testlib_name} SHARED ${testlib_source})
  set_target_properties(${testlib_name} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/testlibs/ COMPILE_FLAGS "-g -O0")
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
  if((${LLVM_VERSION} VERSION_GREATER 6.99.0) AND (${LLVM_VERSION} VERSION_LESS 8.0.0))
    message(STATUS "Adding codegen-validator test")
    configure_file(codegen-validator.sh codegen-validator.sh COPYONLY)
    add_custom_target(codegen-validator COMMAND ./codegen-validator.sh)
    add_test(NAME codegen-validator COMMAND ./codegen-validator.sh ${CMAKE_SOURCE_DIR})
  else()
    message(STATUS "Not building with LLVM 7, skipping codegen-validator test")
  endif()
else()
  message(STATUS "codegen-validator test disabled")
endif()
