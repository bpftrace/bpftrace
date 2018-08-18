add_library(resources headers.c)

function(embed_headers output)
  file(WRITE ${output} "")
  file(GLOB headers *.h)
  foreach(header ${headers})
    get_filename_component(filename ${header} NAME)
    string(MAKE_C_IDENTIFIER ${filename} varname)
    file(READ ${header} contents)
    file(APPEND ${output} "const char ${varname}[] = R\"CONTENTS(${contents})CONTENTS\";\nconst unsigned ${varname}_len = sizeof(${varname});\n")
  endforeach()
endfunction()

embed_headers(${CMAKE_BINARY_DIR}/resources/headers.c)
