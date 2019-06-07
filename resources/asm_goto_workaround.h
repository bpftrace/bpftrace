// linux/types.h is included by default, which will bring
// in asm_volatile_goto definition if permitted based on
// compiler setup and kernel configs.
//
// clang does not support "asm volatile goto" yet.
// So redefine asm_volatile_goto to some invalid asm code.
// We won't execute this code anyway, so we just need to make sure clang is
// able to parse our headers.
//
// From: https://github.com/iovisor/bcc/pull/2133/files

#ifndef __ASM_GOTO_WORKAROUND_H
#define __ASM_GOTO_WORKAROUND_H
#include <linux/types.h>
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#endif
#endif
