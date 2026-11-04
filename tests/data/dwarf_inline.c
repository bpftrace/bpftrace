static __attribute__((always_inline)) inline int inline_target(int x)
{
  volatile int first = x + 7;
  volatile int second = first * 3;
  return second - x;
}

__attribute__((noinline)) int physical_target(int x)
{
  int result = inline_target(x);
  asm volatile("" : "+r"(result));
  return result * 2;
}

int main(void)
{
  return physical_target(3);
}
