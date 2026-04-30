#pragma once

// A constant whose low-order bits are all 1 and is greater than the maximum
// index number. To resolve the verifier's complaint that the off range is too
// large, resulting in "possible" access beyond the range of ARRAY[], we use a
// constant value to constrain `index` to help the verifier.
// Maximum value is EHWPOISON 133 (1000 0101), mask 1111 1111 = 0xff
#define ERROR_INDEX_MASK 0xff
// SIGRTMAX 64 (0100 0000), mask 0111 1111 = 0x7f
#define SIGNAL_INDEX_MASK 0x7f
// sys_pwritev64v2 547 (0010 0010 0011), mask 0011 1111 1111 = 0x3ff
// see linux::arch/x86/entry/syscalls/syscall_64.tbl
#define SYSCALL_INDEX_MASK 0x3ff
