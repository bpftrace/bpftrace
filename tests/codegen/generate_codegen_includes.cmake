# Combine all codegen tests into a single compilation unit to improve build
# performance. https://github.com/iovisor/bpftrace/issues/229
function(generate_codegen_includes output)
  file(REMOVE ${output})
  file(GLOB tests ${TEST_SRC_DIR}/*.cpp)
  file(WRITE ${output} "")
  foreach(test ${tests})
    file(APPEND ${output} "#include \"${test}\"\n")
  endforeach()
endfunction()

generate_codegen_includes(${CMAKE_BINARY_DIR}/codegen_includes.cpp)
