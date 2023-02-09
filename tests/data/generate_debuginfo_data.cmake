# Generates header files that store debuginfo from data_source.c in the form
# of byte arrays

execute_process(COMMAND gcc -g -o data_source.o data_source.c
  WORKING_DIRECTORY ${DATA_SOURCE_DIR})

# Generate btf_data.h from BTF data format
set(ENV{LLVM_OBJCOPY} ${LLVM_OBJCOPY}) # pahole uses LLVM_OBJCOPY env var
execute_process(COMMAND pahole -J data_source.o
  WORKING_DIRECTORY ${DATA_SOURCE_DIR})
execute_process(COMMAND ${LLVM_OBJCOPY} --dump-section .BTF=btf_data data_source.o
  WORKING_DIRECTORY ${DATA_SOURCE_DIR})
execute_process(COMMAND xxd -i btf_data
  OUTPUT_VARIABLE BTF_DATA
  WORKING_DIRECTORY ${DATA_SOURCE_DIR})
execute_process(COMMAND nm data_source.o
  COMMAND awk -v ORS=\\\\n "$2 == \"T\" { print $3 }"
  OUTPUT_VARIABLE FUNC_LIST
  WORKING_DIRECTORY ${DATA_SOURCE_DIR})
configure_file(${DATA_SOURCE_DIR}/btf_data.h.in ${DATA_SOURCE_DIR}/btf_data.h)

if (LIBDW_FOUND)
  # Generate dwarf_data.h from DWARF data format
  execute_process(COMMAND strip --only-keep-debug -o dwarf_data data_source.o
    WORKING_DIRECTORY ${DATA_SOURCE_DIR})
  execute_process(COMMAND xxd -i dwarf_data
    OUTPUT_VARIABLE DWARF_DATA
    WORKING_DIRECTORY ${DATA_SOURCE_DIR})
  configure_file(${DATA_SOURCE_DIR}/dwarf_data.h.in ${DATA_SOURCE_DIR}/dwarf_data.h)
endif()

# Cleanup temporary files
file(REMOVE
  ${DATA_SOURCE_DIR}/data_source.o
  ${DATA_SOURCE_DIR}/dwarf_data
  ${DATA_SOURCE_DIR}/btf_data)
