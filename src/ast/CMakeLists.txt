add_library(ast
  ast.cpp
  codegen_llvm.cpp
  irbuilderbpf.cpp
  printer.cpp
  semantic_analyser.cpp
)

target_include_directories(ast PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_include_directories(ast PUBLIC ${CMAKE_SOURCE_DIR}/src/ast)
target_include_directories(ast PUBLIC ${CMAKE_BINARY_DIR})
target_link_libraries(ast arch)

add_dependencies(ast bcc-build)
ExternalProject_Get_Property(bcc source_dir)
target_include_directories(ast PUBLIC ${source_dir}/src/cc)
