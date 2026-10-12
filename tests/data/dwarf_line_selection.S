#if !defined(__x86_64__) && !defined(__aarch64__)
#error "dwarf_line_selection.S supports x86_64 and aarch64 only"
#endif

.file 1 "dwarf_line_selection.c"
.text
.balign 4
.globl line_selection_target
.type line_selection_target,%function
line_selection_target:
.loc 1 10 1 is_stmt 0
  nop
  ret
.size line_selection_target, .-line_selection_target
.balign 4
.globl line_selection_preferred
.type line_selection_preferred,%function
line_selection_preferred:
.loc 1 10 1 is_stmt 1
  nop
.loc 1 11 1 is_stmt 1
  ret
.size line_selection_preferred, .-line_selection_preferred
.section .note.GNU-stack,"",%progbits
