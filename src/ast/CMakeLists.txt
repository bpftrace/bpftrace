add_library(ast_defs STATIC
  ast.cpp
  context.cpp
  helpers.cpp
  location.cpp
)
add_dependencies(ast_defs parser)
target_link_libraries(ast_defs util)

add_library(ast STATIC
  async_event_types.cpp
  attachpoint_parser.cpp
  codegen_helper.cpp
  diagnostic.cpp
  dibuilderbpf.cpp
  irbuilderbpf.cpp
  pass_manager.cpp
  signal.cpp

  passes/c_macro_expansion.cpp
  passes/clang_parser.cpp
  passes/clang_build.cpp
  passes/named_param.cpp
  passes/codegen_resources.cpp
  passes/config_analyser.cpp
  passes/deprecated.cpp
  passes/field_analyser.cpp
  passes/fold_literals.cpp
  passes/import_scripts.cpp
  passes/link.cpp
  passes/map_sugar.cpp
  passes/macro_expansion.cpp
  passes/pid_filter_pass.cpp
  passes/portability_analyser.cpp
  passes/printer.cpp
  passes/probe_expansion.cpp
  passes/resource_analyser.cpp
  passes/semantic_analyser.cpp
  passes/codegen_llvm.cpp
  passes/resolve_imports.cpp
  passes/return_path_analyser.cpp
  passes/recursion_check.cpp
  passes/type_system.cpp
  passes/unstable_feature.cpp
  passes/usdt_arguments.cpp
)

add_dependencies(ast parser)
target_compile_definitions(ast PRIVATE ${BPFTRACE_FLAGS})
target_link_libraries(ast PRIVATE debugfs tracefs util stdlib ${LIBBPF_LIBRARIES})
target_link_libraries(ast PUBLIC ast_defs arch compiler_core parser btf)

if (NOT SYSTEM_INCLUDE_PATHS EQUAL "auto")
  MESSAGE(STATUS "Using SYSTEM_INCLUDE_PATHS=${SYSTEM_INCLUDE_PATHS}")
endif()
target_compile_definitions(ast PUBLIC SYSTEM_INCLUDE_PATHS="${SYSTEM_INCLUDE_PATHS}")

if(STATIC_LINKING)
  include(Util)

  set(llvm_lib_names
      bpfcodegen
      coverage
      frontenddriver
      frontendhlsl
      frontendopenmp
      ipo
      irreader
      lto
      mcjit
      option
      orcjit
      ${LLVM_TARGETS_TO_BUILD})

  llvm_map_components_to_libnames(llvm_libs ${llvm_lib_names})

  # It's extremely unclear why the clang static libraries export link
  # dependencies on the llvm and clang shared libraries. Regardless, we need
  # this hack to remove them.
  unlink_transitive_dependency("${CLANG_EXPORTED_TARGETS}" "LLVM")
  unlink_transitive_dependency("${CLANG_EXPORTED_TARGETS}" "$<LINK_ONLY:clang-cpp>")

  target_link_libraries(ast PUBLIC libclang_static clangDriver clangFrontend clangCodeGen)
  target_link_libraries(ast PUBLIC ${llvm_libs})
else()
  if (TARGET LLVM)
    # llvm_config macro comes from the LLVM toolchain and will auto-resolve component
    # names to library names. USE_SHARED option will tell llvm_config macro to prefer
    # shared library / DLL on the system over the static libraries
    llvm_config(ast USE_SHARED bpfcodegen ipo irreader mcjit orcjit)
  else()
    # some build environment(e.g facebookexperimental/ExtendedAndroidTools) doesn't
    # have libLLVM.so, drop `USE_SHARED` to avoid forcing link to `-lLLVM`.
    llvm_config(ast bpfcodegen ipo irreader mcjit orcjit)
  endif()

  target_link_libraries(ast PUBLIC libclang clang-cpp)
endif()
