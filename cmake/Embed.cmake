# Functions to embed source files.

find_program(XXD xxd REQUIRED)

function(embed NAME SOURCE)
  cmake_parse_arguments(
    ARG
    ""
    "OUTPUT;HEX;VAR"
    "DEPENDS"
    ${ARGN}
  )
  if (NOT DEFINED ARG_HEX)
    set(ARG_HEX "${NAME}.hex")
  endif ()
  if (NOT DEFINED ARG_VAR)
    set(ARG_VAR "${NAME}")
  endif ()
  if (NOT DEFINED ARG_OUTPUT)
    set(ARG_OUTPUT "${NAME}.h")
  endif ()
  add_custom_command(
    OUTPUT ${ARG_HEX}
    COMMAND ${XXD} -i < ${SOURCE} > ${ARG_HEX}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${SOURCE} ${ARG_DEPENDS}
    VERBATIM
  )
  add_custom_command(
    OUTPUT ${ARG_OUTPUT}
    COMMAND ${CMAKE_COMMAND}
      -DSOURCE=${CMAKE_CURRENT_BINARY_DIR}/${ARG_HEX}
      -DVAR=${ARG_VAR}
      -DNAMESPACE=${ARG_NAMESPACE}
      -DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/${ARG_OUTPUT}
      -DTEMPLATE=${CMAKE_SOURCE_DIR}/cmake/Embed.tmpl
      -P ${CMAKE_SOURCE_DIR}/cmake/EmbedRun.cmake
    DEPENDS
      ${ARG_HEX}
      ${CMAKE_SOURCE_DIR}/cmake/EmbedRun.cmake
      ${CMAKE_SOURCE_DIR}/cmake/Embed.tmpl
    VERBATIM
  )
  add_custom_target(
    ${NAME}
    DEPENDS ${ARG_OUTPUT}
  )
endfunction()
