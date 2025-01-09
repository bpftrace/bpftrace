find_program(GO_EXECUTABLE go)
if(GO_EXECUTABLE)
  add_custom_target(test_extern_go
    COMMAND ${GO_EXECUTABLE} build -o ${CMAKE_CURRENT_BINARY_DIR}/test .
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS main.go go.mod
  )
  add_dependencies(testprogs test_extern_rust)
endif()
