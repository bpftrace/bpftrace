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
  probe.cpp
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
  ${CMAKE_SOURCE_DIR}/src/resolve_cgroupid.cpp
  ${CMAKE_SOURCE_DIR}/src/tracepoint_format_parser.cpp
  ${CMAKE_SOURCE_DIR}/src/types.cpp
  ${CMAKE_SOURCE_DIR}/src/utils.cpp
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
if(HAVE_GET_CURRENT_CGROUP_ID)
  target_compile_definitions(bpftrace PRIVATE HAVE_GET_CURRENT_CGROUP_ID)
endif(HAVE_GET_CURRENT_CGROUP_ID)
target_link_libraries(bpftrace_test arch ast parser resources)

if (STATIC_LINKING)
  target_link_libraries(bpftrace_test ${LIBBCC_LIBRARIES})
  target_link_libraries(bpftrace_test ${LIBBPF_LIBRARY_STATIC})
  target_link_libraries(bpftrace_test ${LIBBCC_LOADER_LIBRARY_STATIC})
else()
  target_link_libraries(bpftrace_test ${LIBBCC_LIBRARIES})
endif()
target_link_libraries(bpftrace_test ${LIBELF_LIBRARIES})

find_package(Threads REQUIRED)

if (OFFLINE_BUILDS)
  include(ExternalProject)
  ExternalProject_Add(gtest-git
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.8.1
    STEP_TARGETS build update
    EXCLUDE_FROM_ALL 1
    UPDATE_DISCONNECTED 1
    )
else()
  include(ExternalProject)
  ExternalProject_Add(gtest-git
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.8.1
    STEP_TARGETS build update
    EXCLUDE_FROM_ALL 1
    )
endif()
add_dependencies(bpftrace_test gtest-git-build)
ExternalProject_Get_Property(gtest-git source_dir binary_dir)
target_include_directories(bpftrace_test PUBLIC ${source_dir}/googletest/include)
target_include_directories(bpftrace_test PUBLIC ${source_dir}/googlemock/include)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/gtest/libgtest_main.a)
target_link_libraries(bpftrace_test ${binary_dir}/googlemock/libgmock.a)
target_link_libraries(bpftrace_test ${CMAKE_THREAD_LIBS_INIT})

add_test(NAME bpftrace_test COMMAND bpftrace_test)

configure_file(runtime-tests.sh runtime-tests.sh COPYONLY)
configure_file(main.py main.py COPYONLY)
configure_file(parser.py parser.py COPYONLY)
configure_file(utils.py utils.py COPYONLY)
file(GLOB runtime_tests runtime/*)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/runtime/)
foreach(runtime_test ${runtime_tests})
  configure_file(${runtime_test} ${CMAKE_CURRENT_BINARY_DIR}/runtime/ COPYONLY)
endforeach()
add_custom_target(runtime-tests COMMAND ./runtime-tests.sh)
add_test(NAME runtime_test COMMAND ./runtime-tests.sh)

# Compile all testprograms, one per .c file for runtime testing
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/testprogs/)
file(GLOB testprogs testprogs/*)
foreach(testprog ${testprogs})
  get_filename_component(bin_name ${testprog} NAME_WE)
  add_executable (${bin_name} ${testprog})
  set_target_properties( ${bin_name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/testprogs/ )
endforeach()

configure_file(tools-parsing-test.sh tools-parsing-test.sh COPYONLY)
add_custom_target(tools-parsing-test COMMAND ./tools-parsing-test.sh)
add_test(NAME tools-parsing-test COMMAND ./tools-parsing-test.sh)
