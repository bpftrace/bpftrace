.section .debug_abbrev,"",%progbits
/* CU: name, language; children. */
.uleb128 1; .uleb128 0x11; .byte 1
.uleb128 3; .uleb128 8
.uleb128 0x13; .uleb128 5
.byte 0,0
/* int base type. */
.uleb128 2; .uleb128 0x24; .byte 0
.uleb128 3; .uleb128 8
.uleb128 0x3e; .uleb128 0xb
.uleb128 0xb; .uleb128 0xb
.byte 0,0
/* Concrete function: origin, low_pc, high_pc. */
.uleb128 3; .uleb128 0x2e; .byte 1
.uleb128 0x31; .uleb128 0x13
.uleb128 0x11; .uleb128 1
.uleb128 0x12; .uleb128 7
.byte 0,0
/* Concrete argument: origin. */
.uleb128 4; .uleb128 5; .byte 0
.uleb128 0x31; .uleb128 0x13
.byte 0,0
/* Abstract function: name, type, inline. */
.uleb128 5; .uleb128 0x2e; .byte 1
.uleb128 3; .uleb128 8
.uleb128 0x49; .uleb128 0x13
.uleb128 0x20; .uleb128 0xb
.byte 0,0
/* Abstract argument: name, type. */
.uleb128 6; .uleb128 5; .byte 0
.uleb128 3; .uleb128 8
.uleb128 0x49; .uleb128 0x13
.byte 0,0
.byte 0

.section .debug_info,"",%progbits
.Lcu:
.long .Lend-.Lversion
.Lversion:
.short 4
.long 0
.byte __SIZEOF_POINTER__
.uleb128 1
.asciz "concrete-first.c"
.short 2
.Lint:
.uleb128 2
.asciz "int"
.byte 5,4
.uleb128 3
.long .Labstract-.Lcu
#if __SIZEOF_POINTER__ == 8
.quad main
#else
.long main
#endif
.quad 1
.uleb128 4
.long .Lleft-.Lcu
.uleb128 4
.long .Lright-.Lcu
.byte 0
.Labstract:
.uleb128 5
.asciz "add_named"
.long .Lint-.Lcu
.byte 3
.Lleft:
.uleb128 6
.asciz "left"
.long .Lint-.Lcu
.Lright:
.uleb128 6
.asciz "right"
.long .Lint-.Lcu
.byte 0,0
.Lend:
.section .note.GNU-stack,"",%progbits
