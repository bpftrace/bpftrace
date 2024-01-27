# This logic needs to be in a separate cmake script b/c file() runs
# at cmake configuration stage and _not_ during build. So this script
# is wrapped in a custom command so that it's only run when necessary.

file(READ ${DWARF_DATA_HEX} DWARF_DATA)

configure_file(${DWARF_DATA_H_IN} ${DWARF_DATA_H})
