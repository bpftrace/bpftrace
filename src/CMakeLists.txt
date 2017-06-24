find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)
find_package(LLVM REQUIRED CONFIG)

bison_target(parser parser.yy ${CMAKE_CURRENT_BINARY_DIR}/parser.tab.cc)
flex_target(lexer lexer.l ${CMAKE_CURRENT_BINARY_DIR}/lex.yy.cc)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

set(CMAKE_EXE_LINKER_FLAGS "-static")
add_executable(bpftrace
  ast.cpp
  attached_probe.cpp
  bpftrace.cpp
  codegen_llvm.cpp
  driver.cpp
  irbuilderbpf.cpp
  lex.yy.cc
  main.cpp
  map.cpp
  mapkey.cpp
  parser.tab.cc
  printer.cpp
  semantic_analyser.cpp
  types.cpp
)

target_link_libraries(bpftrace arch)

llvm_map_components_to_libnames(llvm_libs bpfcodegen ipo irreader mcjit)
target_link_libraries(bpftrace ${llvm_libs})

add_dependencies(bpftrace bcc-build)
ExternalProject_Get_Property(bcc source_dir binary_dir)
include_directories(${source_dir}/src/cc)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbpf.a)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbcc-loader-static.a)
target_link_libraries(bpftrace ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../../usr/lib/x86_64-linux-gnu/libelf.a)
