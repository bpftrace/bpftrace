#line 1 "dwarf_function_consistency_input.c"
static __attribute__((always_inline)) inline int inline_target(int value)
{
  return value + 1;
}

__attribute__((noinline)) int physical_first(int value)
{
#line 3 "dwarf_function_consistency_input.c"
  return value + 2;
}

__attribute__((noinline)) int physical_second(int value)
{
#line 20 "dwarf_function_consistency_input.c"
  return inline_target(value);
}

int main(void)
{
  return physical_first(1) + physical_second(2);
}
