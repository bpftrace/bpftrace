add_library(ast_defs ast.cpp)

add_library(ast
  async_event_types.cpp
  attachpoint_parser.cpp
  elf_parser.cpp
  int_parser.cpp
  irbuilderbpf.cpp
  pass_manager.cpp
  signal.cpp
  visitors.cpp

  passes/field_analyser.cpp
  passes/portability_analyser.cpp
  passes/printer.cpp
  passes/resource_analyser.cpp
  passes/semantic_analyser.cpp
  passes/codegen_llvm.cpp
)

target_include_directories(ast_defs PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_include_directories(ast_defs PUBLIC ${CMAKE_SOURCE_DIR}/src/ast)
target_include_directories(ast_defs PUBLIC ${CMAKE_BINARY_DIR})
target_link_libraries(ast ast_defs arch parser)

add_dependencies(ast_defs parser)

target_compile_definitions(ast PRIVATE ${BPFTRACE_FLAGS})

if (STATIC_LINKING)
  set(clang_libs
      clangAST
      clangAnalysis
      clangBasic
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
      frontendopenmp
      ipo
      irreader
      mcjit
      option
      orcjit
      ${LLVM_TARGETS_TO_BUILD})


  if(EMBED_USE_LLVM)
    target_link_libraries(ast "-Wl,--start-group" ${CLANG_EMBEDDED_CMAKE_TARGETS} ${LLVM_EMBEDDED_CMAKE_TARGETS} "-Wl,--end-group")
  else()
    llvm_map_components_to_libnames(llvm_libs ${llvm_lib_names})

    if(TARGET libclang_static)
      target_link_libraries(ast libclang_static)
    else()
      # old LLVM versions don't export libclang_static in ClangTargets.cmake; fall back to
      # libclang.a in that case
      target_link_libraries(ast libclang.a)    
    endif()

    target_link_libraries(ast ${clang_libs})
    target_link_libraries(ast ${llvm_libs})
  endif()

  if(STATIC_LIBC)
    unlink_transitive_dependency("${CLANG_EXPORTED_TARGETS}" "LLVM")
  endif()

else()
  find_library(found_LLVM LLVM HINTS ${LLVM_LIBRARY_DIRS})
  if(found_LLVM)
    target_link_libraries(ast LLVM)
  else()
    llvm_map_components_to_libnames(_llvm_libs bpfcodegen ipo irreader mcjit orcjit ${LLVM_TARGETS_TO_BUILD})
    llvm_expand_dependencies(llvm_libs ${_llvm_libs})
    target_link_libraries(ast ${llvm_libs})
  endif()
  target_link_libraries(ast libclang)
endif()
