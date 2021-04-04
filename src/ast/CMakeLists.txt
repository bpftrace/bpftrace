add_library(ast
  ast.cpp
  attachpoint_parser.cpp
  codegen_llvm.cpp
  fake_map.cpp
  field_analyser.cpp
  irbuilderbpf.cpp
  pass_manager.cpp
  printer.cpp
  semantic_analyser.cpp
  signal.cpp
  visitors.cpp

  passes/remove_positional_params.cpp
)

target_include_directories(ast PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_include_directories(ast PUBLIC ${CMAKE_SOURCE_DIR}/src/ast)
target_include_directories(ast PUBLIC ${CMAKE_BINARY_DIR})
target_link_libraries(ast arch)

if (HAVE_BCC_KFUNC)
  target_compile_definitions(ast PRIVATE HAVE_BCC_KFUNC)
endif(HAVE_BCC_KFUNC)

add_dependencies(ast parser)

if (STATIC_LINKING)
  set(clang_libs
      clangAST
      clangAnalysis
      clangBasic
      clangDriver
      clangEdit
      clangFormat
      clangFrontend
      clangIndex
      clangLex
      clangParse
      clangRewrite
      clangSema
      clangSerialization
      clangToolingCore)

  if(EMBED_CLANG)
    list(APPEND clang_libs clangToolingInclusions)
    if(EMBED_LIBCLANG_ONLY)
      unlink_transitive_dependency("${CLANG_EXPORTED_TARGETS}" "LLVM")
    endif()
    target_link_libraries(ast ${CLANG_EMBEDDED_CMAKE_TARGETS})
  else()
    list(INSERT clang_libs 0 libclang.a)
  endif()

  if(EMBED_LLVM)
    target_link_libraries(ast ${LLVM_EMBEDDED_CMAKE_TARGETS})
  else()
    llvm_map_components_to_libnames(llvm_libs bpfcodegen ipo irreader mcjit option orcjit ${LLVM_TARGETS_TO_BUILD})
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
