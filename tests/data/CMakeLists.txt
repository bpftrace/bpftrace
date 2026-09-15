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
