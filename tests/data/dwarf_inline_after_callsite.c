#line 30 "dwarf_inline_after_callsite_input.c"
static __attribute__((always_inline)) inline int inline_late(int value)
{
  return value + 1;
}

#line 10 "dwarf_inline_after_callsite_input.c"
__attribute__((noinline)) int physical_late(int value)
{
  return inline_late(value);
}

int main(void)
{
  return physical_late(1);
}
