add_compile_options("-Wno-undef")
add_compile_options("-Wno-switch-default")
add_compile_options("-Wno-switch-enum")

add_executable(bpftrace_test
  ast.cpp
  bpftrace.cpp
  clang_parser.cpp
  main.cpp
  parser.cpp
  probe.cpp
  semantic_analyser.cpp
  tracepoint_format_parser.cpp
  utils.cpp

  codegen/general.cpp
  codegen/bitshift_left.cpp
  codegen/bitshift_right.cpp
  codegen/builtin_arg.cpp
  codegen/builtin_comm.cpp
  codegen/builtin_cpu.cpp
  codegen/builtin_ctx.cpp
  codegen/builtin_curtask.cpp
  codegen/builtin_func.cpp
  codegen/builtin_func_wild.cpp
  codegen/builtin_nsecs.cpp
  codegen/builtin_pid_tid.cpp
  codegen/builtin_probe.cpp
  codegen/builtin_probe_wild.cpp
  codegen/builtin_rand.cpp
  codegen/builtin_retval.cpp
  codegen/builtin_stack.cpp
  codegen/builtin_uid_gid.cpp
  codegen/builtin_username.cpp
  codegen/builtin_ustack.cpp
  codegen/call_avg.cpp
  codegen/call_cgroup.cpp
  codegen/call_clear.cpp
  codegen/call_count.cpp
  codegen/call_delete.cpp
  codegen/call_exit.cpp
  codegen/call_hist.cpp
  codegen/call_lhist.cpp
  codegen/call_max.cpp
  codegen/call_min.cpp
  codegen/call_print.cpp
  codegen/call_printf.cpp
  codegen/call_reg.cpp
  codegen/call_stats.cpp
  codegen/call_str.cpp
  codegen/call_sum.cpp
  codegen/call_system.cpp
  codegen/call_time.cpp
  codegen/call_usym_key.cpp
  codegen/call_zero.cpp
  codegen/dereference.cpp
  codegen/empty_function.cpp
  codegen/if_else_printf.cpp
  codegen/if_else_variable.cpp
  codegen/if_nested_printf.cpp
  codegen/if_printf.cpp
  codegen/if_variable.cpp
  codegen/int_propagation.cpp
  codegen/logical_and.cpp
  codegen/logical_or.cpp
  codegen/map_assign_int.cpp
  codegen/map_assign_string.cpp
  codegen/map_key_int.cpp
  codegen/map_key_string.cpp
  codegen/multiple_identical_probes.cpp
  codegen/pred_binop.cpp
  codegen/string_equal_comparison.cpp
  codegen/string_not_equal_comparison.cpp
  codegen/string_propagation.cpp
  codegen/struct_char.cpp
  codegen/struct_integer_ptr.cpp
  codegen/struct_integers.cpp
  codegen/struct_long.cpp
  codegen/struct_nested_struct_anon.cpp
  codegen/struct_nested_struct_named.cpp
  codegen/struct_nested_struct_ptr_named.cpp
  codegen/struct_save.cpp
  codegen/struct_save_nested.cpp
  codegen/struct_save_string.cpp
  codegen/struct_short.cpp
  codegen/struct_string_array.cpp
  codegen/struct_string_ptr.cpp
  codegen/ternary_int.cpp
  codegen/ternary_str.cpp
  codegen/unroll.cpp
  codegen/variable.cpp

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
)

if(HAVE_NAME_TO_HANDLE_AT)
  target_compile_definitions(bpftrace_test PRIVATE HAVE_NAME_TO_HANDLE_AT=1)
endif(HAVE_NAME_TO_HANDLE_AT)
target_link_libraries(bpftrace_test arch ast parser resources)

ExternalProject_Get_Property(bcc source_dir binary_dir)
target_include_directories(bpftrace_test PUBLIC ${source_dir}/src/cc)
target_link_libraries(bpftrace_test ${binary_dir}/src/cc/libbpf.a)
target_link_libraries(bpftrace_test ${binary_dir}/src/cc/libbcc-loader-static.a)
target_link_libraries(bpftrace_test ${binary_dir}/src/cc/libbcc.a)
target_link_libraries(bpftrace_test ${binary_dir}/src/cc/frontends/clang/libclang_frontend.a)
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
