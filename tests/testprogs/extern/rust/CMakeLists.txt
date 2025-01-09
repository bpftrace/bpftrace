find_program(CARGO_EXECUTABLE cargo)
if(CARGO_EXECUTABLE)
  add_custom_target(test_extern_rust
    COMMAND ${CMAKE_COMMAND} -E env "RUSTFLAGS=-C symbol_mangling_version=v0" ${CARGO_EXECUTABLE} build --target-dir ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS src/main.rs Cargo.toml
  )
  add_dependencies(testprogs test_extern_rust)
endif()
