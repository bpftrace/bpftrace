#include <unistd.h>

struct Foo {
  int a, b, c;
  int *x;
};

int uprobeFunction1(int x, Foo foo)
{
  return x + foo.c;
}

int uprobeArray(int (&array)[10])
{
  return array[0];
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  // usleep(1000000);

  int x = 42;
  Foo foo{ 1, 2, 3, &x };
  uprobeFunction1(x, foo);

  return 0;
}
