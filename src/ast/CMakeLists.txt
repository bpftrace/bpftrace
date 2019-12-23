add_library(ast
  ast.cpp
  codegen_llvm.cpp
  field_analyser.cpp
  irbuilderbpf.cpp
  printer.cpp
  semantic_analyser.cpp
)

if(HAVE_GET_CURRENT_CGROUP_ID)
  target_compile_definitions(ast PRIVATE HAVE_GET_CURRENT_CGROUP_ID)
endif(HAVE_GET_CURRENT_CGROUP_ID)

if(HAVE_SEND_SIGNAL)
  target_compile_definitions(ast PRIVATE HAVE_SEND_SIGNAL)
endif(HAVE_SEND_SIGNAL)

target_include_directories(ast PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_include_directories(ast PUBLIC ${CMAKE_SOURCE_DIR}/src/ast)
target_include_directories(ast PUBLIC ${CMAKE_BINARY_DIR})
target_link_libraries(ast arch)

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
    target_link_libraries(ast ${CLANG_EMBEDDED_CMAKE_TARGETS})
    list(APPEND clang_libs clangToolingInclusions)
    if(EMBED_LIBCLANG_ONLY)
      foreach(clang_lib IN LISTS clang_libs)
        get_target_property(link_libraries ${clang_lib} INTERFACE_LINK_LIBRARIES)
        string(REPLACE "LLVM" "" static_only_libs "${link_libraries}")
        fix_llvm_linkflags(${clang_lib} "${static_only_libs}")
      endforeach(clang_lib)
    endif()
  else()
    list(INSERT clang_libs 0 libclang.a)
  endif()

  if(EMBED_LLVM)
    target_link_libraries(ast ${LLVM_EMBEDDED_CMAKE_TARGETS})
  else()
    llvm_map_components_to_libnames(llvm_libs bpfcodegen ipo irreader mcjit orcjit ${LLVM_TARGETS_TO_BUILD})
    target_link_libraries(ast ${clang_libs})
    target_link_libraries(ast ${llvm_libs})
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
