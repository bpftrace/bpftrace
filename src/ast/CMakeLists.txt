add_library(ast_defs STATIC ast.cpp)
add_dependencies(ast_defs parser)

add_library(ast STATIC
  async_event_types.cpp
  attachpoint_parser.cpp
  codegen_helper.cpp
  dibuilderbpf.cpp
  int_parser.cpp
  irbuilderbpf.cpp
  pass_manager.cpp
  signal.cpp

  passes/codegen_resources.cpp
  passes/config_analyser.cpp
  passes/field_analyser.cpp
  passes/portability_analyser.cpp
  passes/printer.cpp
  passes/resource_analyser.cpp
  passes/semantic_analyser.cpp
  passes/codegen_llvm.cpp
  passes/return_path_analyser.cpp
)

add_dependencies(ast parser)
target_compile_definitions(ast PRIVATE ${BPFTRACE_FLAGS})
target_link_libraries(ast PUBLIC ast_defs arch compiler_core parser)

if(STATIC_LINKING)
  include(Util)

  set(clang_libs
      clangAST
      clangAnalysis
      clangBasic
      clangCodeGen
      clangDriver
      clangEdit
      clangFormat
      clangFrontend
      clangIncludeFixerPlugin
      clangIndex
      clangLex
      clangParse
      clangRewrite
      clangSema
      clangSerialization
      clangTidyPlugin
      clangToolingCore)

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

  if(TARGET libclang_static)
    target_link_libraries(ast PUBLIC libclang_static)
  else()
    # old LLVM versions don't export libclang_static in ClangTargets.cmake; fall back to
    # libclang.a in that case
    target_link_libraries(ast PUBLIC libclang.a)
  endif()

  target_link_libraries(ast PUBLIC ${clang_libs})
  target_link_libraries(ast PUBLIC ${llvm_libs})
else()
  # llvm_config macro comes from the LLVM toolchain and will auto-resolve component
  # names to library names. USE_SHARED option will tell llvm_config macro to prefer
  # shared library / DLL on the system over the static libraries
  llvm_config(ast USE_SHARED bpfcodegen ipo irreader mcjit orcjit)
  target_link_libraries(ast PUBLIC libclang)
endif()
