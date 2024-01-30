#pragma once

#if defined(__arm__)
// Force the compiler to generate A32 instructions for the two trigger functions
// to ensure they end up being 4-byte (UPROBE_SWBP_INSN_SIZE) aligned, otherwise
// uprobe_register() fails with EINVAL (see kernel/events/uprobes.c).
#define __target_attr __attribute__((target("arm")))
#else
#define __target_attr
#endif

using trigger_fn_t = void (*)();

extern "C" {
void __attribute__((noinline)) __target_attr BEGIN_trigger()
{
  asm("");
}
void __attribute__((noinline)) __target_attr END_trigger()
{
  asm("");
}
}
