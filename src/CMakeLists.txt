cmake_minimum_required(VERSION 2.8.12)
project(bpftrace)

add_compile_options("-std=c++14")
add_compile_options("-Wall")
add_compile_options("-Wextra")
add_compile_options("-Wundef")
add_compile_options("-Wpointer-arith")
add_compile_options("-Wcast-align")
add_compile_options("-Wwrite-strings")
add_compile_options("-Wcast-qual")
add_compile_options("-Wswitch-default")
add_compile_options("-Wswitch-enum")
add_compile_options("-Wconversion")
add_compile_options("-Wunreachable-code")
add_compile_options("-Wformat=2")
add_compile_options("-Wstrict-overflow=5")
add_compile_options("-Wdisabled-optimization")
add_compile_options("-pedantic")

find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)
find_package(LLVM REQUIRED CONFIG)

bison_target(parser parser.yy ${CMAKE_CURRENT_BINARY_DIR}/parser.tab.cc)
flex_target(lexer lexer.l ${CMAKE_CURRENT_BINARY_DIR}/lex.yy.cc)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_executable(bpftrace main.cpp driver.cpp parser.tab.cc lex.yy.cc ast.cpp printer.cpp codegen_llvm.cpp map.cpp semantic_analyser.cpp bpftrace.cpp)

llvm_map_components_to_libnames(llvm_libs irreader bpfcodegen mcjit)
target_link_libraries(bpftrace ${llvm_libs})

include(ExternalProject)
ExternalProject_Add(bcc
  GIT_REPOSITORY https://github.com/iovisor/bcc
  STEP_TARGETS build update
  EXCLUDE_FROM_ALL 1
  UPDATE_DISCONNECTED 1
)
add_dependencies(bpftrace bcc-build)
ExternalProject_Get_Property(bcc source_dir binary_dir)
include_directories(${source_dir}/src/cc)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbcc.a)
target_link_libraries(bpftrace ${binary_dir}/src/cc/libbcc-loader-static.a)
