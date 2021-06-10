add_library(ast
  ast.cpp
  attachpoint_parser.cpp
  codegen_llvm.cpp
  fake_map.cpp
  field_analyser.cpp
  irbuilderbpf.cpp
  pass_manager.cpp
  portability_analyser.cpp
  printer.cpp
  resource_analyser.cpp
  semantic_analyser.cpp
  signal.cpp
  visitors.cpp
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

  set(llvm_lib_names
      bpfcodegen
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
