include(BuildBPF)
include(Embed)

bpf(
  data_source
  BTF       data_source.btf
  FUNCTIONS data_source.funcs
  BINARY    data_source.exe
)

embed(
  data_source_btf
  data_source.btf
  OUTPUT data_source_btf.h
  VAR btf_data
)

embed(
  data_source_funcs
  data_source.funcs
  OUTPUT data_source_funcs.h
  VAR func_list
)

embed(
  data_source_dwarf
  ${CMAKE_CURRENT_BINARY_DIR}/data_source.exe
  OUTPUT data_source_dwarf.h
  VAR dwarf_data
)

# BTF doesn't support C++, so we only generate a data_source_cxx executable
# to run the field_analyser tests on.
add_executable(data_source_cxx data_source_cxx.cpp)
target_compile_options(data_source_cxx PRIVATE -g)

