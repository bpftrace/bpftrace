add_library(ast
  ast.cpp
  codegen_llvm.cpp
  irbuilderbpf.cpp
  printer.cpp
  semantic_analyser.cpp
)

if(HAVE_GET_CURRENT_CGROUP_ID)
  target_compile_definitions(ast PRIVATE HAVE_GET_CURRENT_CGROUP_ID)
endif(HAVE_GET_CURRENT_CGROUP_ID)

target_include_directories(ast PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_include_directories(ast PUBLIC ${CMAKE_SOURCE_DIR}/src/ast)
target_include_directories(ast PUBLIC ${CMAKE_BINARY_DIR})
target_link_libraries(ast arch)

add_dependencies(ast parser)

if (STATIC_LINKING)
  set(clang_libs
      libclang.a
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
  llvm_map_components_to_libnames(llvm_libs bpfcodegen ipo irreader mcjit orcjit ${LLVM_TARGETS_TO_BUILD})
  target_link_libraries(ast ${clang_libs})
  target_link_libraries(ast ${llvm_libs})
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
