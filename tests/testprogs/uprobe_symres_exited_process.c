#include <unistd.h>

__attribute__((noinline)) int test()
{
  return 42;
}

__attribute__((noinline)) int test2()
{
  return test();
}

int main()
{
  sleep(3);
  test2();
}
