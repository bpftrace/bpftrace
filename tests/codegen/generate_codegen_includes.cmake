# Combine all codegen tests into a single compilation unit to improve build
# performance. https://github.com/bpftrace/bpftrace/issues/229
function(generate_codegen_includes output tests)
  file(REMOVE ${output})
  file(WRITE ${output} "")
  foreach(test ${tests})
    file(APPEND ${output} "#include \"${test}\"\n")
  endforeach()
endfunction()

separate_arguments(CODEGEN_SOURCES NATIVE_COMMAND ${CODEGEN_SOURCES})
generate_codegen_includes("${CODEGEN_INCLUDES_CPP}" "${CODEGEN_SOURCES}")
