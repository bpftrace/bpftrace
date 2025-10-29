include(Embed)

# The standard library is effectively a bunch of embedded files.
#
# The data layout is standardized by `stdlib.h`, but we generate
# stdlib.c which includes the relevant generated headers.
#
# * Basically, everything here that is `*.c`, `*.h` and `*.bt` goes
#   into the `stdlib` embedded directory. Structure is preserved.
# * Everything that is in `include` goes into `include` and is
#   available by default to extensions.
# * The `libbpf` header are embedded in `include` also.

file(GLOB_RECURSE STDLIB_SOURCES "*.c" "*.h" "*.bt")
file(GLOB_RECURSE PUBLIC_HEADERS "include/*.h")
file(GLOB_RECURSE TEST_SCRIPTS "*_test.bt")
file(GLOB_RECURSE BPF_HEADERS "${LIBBPF_INCLUDE_DIRS}/bpf/*.h")
list(REMOVE_ITEM STDLIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/stdlib.h")
list(REMOVE_ITEM STDLIB_SOURCES ${PUBLIC_HEADERS})
list(REMOVE_ITEM STDLIB_SOURCES ${TEST_SCRIPTS})

function(add_stdlib_source PREFIX FILENAME)
  # Generate our embedded header.
  get_filename_component(name "${FILENAME}" NAME)
  string(REPLACE "." "_" header_name "${name}")
  string(REPLACE "/" "_" rule_name "${PREFIX}/${header_name}")
  string(REPLACE "-" "_" rule_name "${rule_name}")
  embed(
    ${rule_name}
    ${FILENAME}
    OUTPUT  ${PREFIX}/${header_name}.h
    VAR     ${rule_name}
  )

  # Add the file to the list of rules we need, and add the original
  # source file to the list of sources we need to depend on.
  list(APPEND STDLIB_TARGETS "${rule_name}")
  set(STDLIB_TARGETS "${STDLIB_TARGETS}" PARENT_SCOPE)

  # Set globals that are used to configure the template.
  set(STDLIB_INCLUDES "${STDLIB_INCLUDES}
#include \"${PREFIX}/${header_name}.h\"" PARENT_SCOPE)
  set(STDLIB_FILES "${STDLIB_FILES}
  { \"${PREFIX}/${name}\", make_view(${rule_name}, sizeof(${rule_name})) },"
  PARENT_SCOPE)
endfunction()

foreach(filename ${STDLIB_SOURCES})
  string(REGEX REPLACE "^${CMAKE_CURRENT_SOURCE_DIR}/" "" suffix "${filename}")
  get_filename_component(prefix "stdlib/${suffix}" DIRECTORY)
  add_stdlib_source("${prefix}" "${filename}")
endforeach()
foreach(filename ${PUBLIC_HEADERS})
  string(REGEX REPLACE "^${CMAKE_CURRENT_SOURCE_DIR}/include/" "" suffix "${filename}")
  get_filename_component(prefix "include/${suffix}" DIRECTORY)
  add_stdlib_source("${prefix}" "${filename}")
endforeach()
foreach(filename ${BPF_HEADERS})
  string(REGEX REPLACE "^${LIBBPF_INCLUDE_DIRS}/" "" suffix "${filename}")
  get_filename_component(prefix "include/${suffix}" DIRECTORY)
  add_stdlib_source("${prefix}" "${filename}")
endforeach()

configure_file(stdlib.cpp.in stdlib.cpp)
add_library(stdlib STATIC ${CMAKE_CURRENT_BINARY_DIR}/stdlib.cpp)
add_dependencies(stdlib ${STDLIB_TARGETS})
