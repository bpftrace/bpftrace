include(BuildBPF)
include(Embed)

# Define the DIE order explicitly: compiler-generated DWARF may put the
# abstract function first and leave inherited parameter names untested.
add_custom_command(
  OUTPUT dwarf_origin
  COMMAND ${GCC} -no-pie ${CMAKE_CURRENT_SOURCE_DIR}/dwarf_origin.c
          ${CMAKE_CURRENT_SOURCE_DIR}/dwarf_origin.S
          -o ${CMAKE_CURRENT_BINARY_DIR}/dwarf_origin
  DEPENDS dwarf_origin.c dwarf_origin.S
  VERBATIM
)
add_custom_target(dwarf_origin_fixture DEPENDS dwarf_origin)

if(SOURCE_LOCATION_FIXTURES)
  add_custom_command(
    OUTPUT dwarf_inline
    COMMAND ${GCC} -O2 -g -no-pie
            ${CMAKE_CURRENT_SOURCE_DIR}/dwarf_inline.c
            -o ${CMAKE_CURRENT_BINARY_DIR}/dwarf_inline
    DEPENDS dwarf_inline.c
    VERBATIM
  )
  add_custom_target(dwarf_inline_fixture DEPENDS dwarf_inline)

  add_custom_command(
    OUTPUT dwarf_line_selection
    COMMAND ${GCC} -g -Wa,--gdwarf-4 -no-pie
            ${CMAKE_CURRENT_SOURCE_DIR}/dwarf_line_selection_main.c
            ${CMAKE_CURRENT_SOURCE_DIR}/dwarf_line_selection.S
            -o ${CMAKE_CURRENT_BINARY_DIR}/dwarf_line_selection
    DEPENDS dwarf_line_selection_main.c dwarf_line_selection.S
    VERBATIM
  )
  add_custom_target(dwarf_line_selection_fixture DEPENDS dwarf_line_selection)

  add_custom_command(
    OUTPUT dwarf_function_consistency
    COMMAND ${GCC} -O2 -g -fno-toplevel-reorder -no-pie
            ${CMAKE_CURRENT_SOURCE_DIR}/dwarf_function_consistency.c
            -o ${CMAKE_CURRENT_BINARY_DIR}/dwarf_function_consistency
    DEPENDS dwarf_function_consistency.c
    VERBATIM
  )
  add_custom_target(
    dwarf_function_consistency_fixture
    DEPENDS dwarf_function_consistency
  )

  add_custom_command(
    OUTPUT dwarf_inline_after_callsite
    COMMAND ${GCC} -O2 -g -no-pie
            ${CMAKE_CURRENT_SOURCE_DIR}/dwarf_inline_after_callsite.c
            -o ${CMAKE_CURRENT_BINARY_DIR}/dwarf_inline_after_callsite
    DEPENDS dwarf_inline_after_callsite.c
    VERBATIM
  )
  add_custom_target(
    dwarf_inline_after_callsite_fixture
    DEPENDS dwarf_inline_after_callsite
  )
endif()

bpf(
  data_source
  BTF       data_source.btf
  FUNCTIONS data_source.funcs
  BINARY    data_source_exe
)

embed(
  data_source_btf
  data_source.btf
  OUTPUT  data_source_btf.h
  VAR     btf_data
  DEPENDS data_source
)

embed(
  data_source_dwarf
  data_source_exe
  OUTPUT  data_source_dwarf.h
  VAR     dwarf_data
  DEPENDS data_source
)

# BTF doesn't support C++, so we only generate a data_source_cxx executable
# to run the field_analyser tests on.
add_executable(data_source_cxx data_source_cxx.cpp)
target_compile_options(data_source_cxx PRIVATE -g)
