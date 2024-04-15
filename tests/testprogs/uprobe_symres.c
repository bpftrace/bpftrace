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
  test2();
  sleep(5);
}
