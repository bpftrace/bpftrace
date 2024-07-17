# Generates header files that store debuginfo from data_source.c in the form
# of byte arrays

find_program(XXD xxd REQUIRED)
find_program(PAHOLE pahole REQUIRED)
find_program(LLVM_OBJCOPY
  NAMES llvm-objcopy llvm-objcopy-${LLVM_VERSION_MAJOR} llvm${LLVM_VERSION_MAJOR}-objcopy
  REQUIRED)
find_program(NM nm REQUIRED)
find_program(AWK awk REQUIRED)
find_program(STRIP strip REQUIRED)

# Build data_source.o and inject BTF into it
set(DATA_SOURCE_C ${CMAKE_CURRENT_SOURCE_DIR}/data_source.c)
set(DATA_SOURCE_O ${CMAKE_CURRENT_BINARY_DIR}/data_source.o)
add_custom_command(
  OUTPUT ${DATA_SOURCE_O}
  COMMAND gcc -g -o ${DATA_SOURCE_O} ${DATA_SOURCE_C}
  # pahole uses LLVM_OBJCOPY env var.
  # We must hack it like this b/c cmake does not support setting env vars at build time
  COMMAND bash -c "LLVM_OBJCOPY=${LLVM_OBJCOPY} pahole -J ${DATA_SOURCE_O}"
  DEPENDS ${DATA_SOURCE_C})
add_custom_target(data_source_o DEPENDS ${DATA_SOURCE_O})

# Generate btf_data from BTF in data_source.o
set(BTF_DATA_FILE ${CMAKE_CURRENT_BINARY_DIR}/btf_data)
add_custom_command(
  OUTPUT ${BTF_DATA_FILE}
  COMMAND ${LLVM_OBJCOPY} --dump-section .BTF=${BTF_DATA_FILE} ${DATA_SOURCE_O}
  DEPENDS data_source_o)

# Generate btf_data.hex from btf_data
set(BTF_DATA_HEX ${CMAKE_CURRENT_BINARY_DIR}/btf_data.hex)
add_custom_command(
  OUTPUT ${BTF_DATA_HEX}
  COMMAND xxd -i < ${BTF_DATA_FILE} > ${BTF_DATA_HEX}
  DEPENDS ${BTF_DATA_FILE})

# Generate func_list.hex from data_source.o
set(FUNC_LIST_HEX ${CMAKE_CURRENT_BINARY_DIR}/func_list.hex)
add_custom_command(
  OUTPUT ${FUNC_LIST_HEX}
  COMMAND nm ${DATA_SOURCE_O} | awk -v ORS=\\\\n "$2 == \"T\" { print $3 }" > ${FUNC_LIST_HEX}
  VERBATIM
  DEPENDS data_source_o)

if(${LLDB_FOUND})
  # Generate dwarf_data from data_source.o
  set(DWARF_DATA_FILE ${CMAKE_CURRENT_BINARY_DIR}/dwarf_data)
  add_custom_command(
    OUTPUT ${DWARF_DATA_FILE}
    COMMAND strip --only-keep-debug -o ${DWARF_DATA_FILE} ${DATA_SOURCE_O}
    DEPENDS data_source_o)

  # Generate dwarf_data.hex from dwarf_data
  set(DWARF_DATA_HEX ${CMAKE_CURRENT_BINARY_DIR}/dwarf_data.hex)
  add_custom_command(
    OUTPUT ${DWARF_DATA_HEX}
    COMMAND xxd -i < ${DWARF_DATA_FILE} > ${DWARF_DATA_HEX}
    DEPENDS ${DWARF_DATA_FILE})

  set(CONFIGURE_DWARF_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/configure_dwarf_headers.cmake)
  set(DWARF_DATA_H_IN ${CMAKE_CURRENT_SOURCE_DIR}/dwarf_data.h.in)
  set(DWARF_DATA_H ${CMAKE_CURRENT_BINARY_DIR}/dwarf_data.h)

  add_custom_command(
    OUTPUT ${DWARF_DATA_H}
    COMMAND
      ${CMAKE_COMMAND}
      -DFUNC_LIST_HEX=${FUNC_LIST_HEX}
      -DDWARF_DATA_HEX=${DWARF_DATA_HEX}
      -DDWARF_DATA_H_IN=${DWARF_DATA_H_IN}
      -DDWARF_DATA_H=${DWARF_DATA_H}
      -P ${CONFIGURE_DWARF_HEADERS}
    DEPENDS ${FUNC_LIST_HEX} ${DWARF_DATA_HEX} ${CONFIGURE_DWARF_HEADERS})

  add_custom_target(debuginfo_dwarf_data DEPENDS ${DWARF_DATA_H})
endif()

set(CONFIGURE_BTF_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/configure_btf_headers.cmake)
set(BTF_DATA_H_IN ${CMAKE_CURRENT_SOURCE_DIR}/btf_data.h.in)
set(BTF_DATA_H ${CMAKE_CURRENT_BINARY_DIR}/btf_data.h)
add_custom_command(
  OUTPUT ${BTF_DATA_H}
  COMMAND
    ${CMAKE_COMMAND}
    -DBTF_DATA_HEX=${BTF_DATA_HEX}
    -DFUNC_LIST_HEX=${FUNC_LIST_HEX}
    -DBTF_DATA_H_IN=${BTF_DATA_H_IN}
    -DBTF_DATA_H=${BTF_DATA_H}
    -P ${CONFIGURE_BTF_HEADERS}
  DEPENDS ${BTF_DATA_HEX} ${FUNC_LIST_HEX} ${CONFIGURE_BTF_HEADERS})

add_custom_target(debuginfo_btf_data DEPENDS ${BTF_DATA_H})
