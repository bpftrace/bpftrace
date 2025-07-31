include(BuildBPF)
include(Embed)

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
  data_source_funcs
  data_source.funcs
  OUTPUT  data_source_funcs.h
  VAR     func_list
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

# Build an object for the loader unit tests.
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/native_object.o
    COMMAND ${CMAKE_C_COMPILER}
      -fPIC -fno-unwind-tables -fno-asynchronous-unwind-tables
      -c ${CMAKE_CURRENT_SOURCE_DIR}/native_object.c
      -o ${CMAKE_CURRENT_BINARY_DIR}/native_object.o
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/native_object.c
)

embed(
  data_source_native_object
  native_object.o
  OUTPUT data_source_native_object.h
  VAR native_object
)
