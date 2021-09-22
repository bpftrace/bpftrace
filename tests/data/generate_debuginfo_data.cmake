# Generates dwarf_data.h that stores DWARF from data_source.c in the form of
# a byte array
execute_process(COMMAND gcc -g -o data_source.o data_source.c
  WORKING_DIRECTORY ${DATA_SOURCE_DIR})
execute_process(COMMAND strip --only-keep-debug -o dwarf_data data_source.o
  WORKING_DIRECTORY ${DATA_SOURCE_DIR})
execute_process(COMMAND xxd -i dwarf_data
  OUTPUT_VARIABLE DWARF_DATA
  WORKING_DIRECTORY ${DATA_SOURCE_DIR})
configure_file(${DATA_SOURCE_DIR}/dwarf_data.h.in ${DATA_SOURCE_DIR}/dwarf_data.h)

# Cleanup temporary files
file(REMOVE
  ${DATA_SOURCE_DIR}/data_source.o
  ${DATA_SOURCE_DIR}/dwarf_data)