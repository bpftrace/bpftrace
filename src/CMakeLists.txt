cmake_minimum_required(VERSION 2.8.12)
project(bpftrace)

find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)

bison_target(parser parser.yy ${CMAKE_CURRENT_BINARY_DIR}/parser.tab.cc)
flex_target(lexer lexer.l ${CMAKE_CURRENT_BINARY_DIR}/lex.yy.cc)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(bpftrace main.cpp ast.cpp parser.tab.cc lex.yy.cc)
