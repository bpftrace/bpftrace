#include <unistd.h>

int GLOBAL_A = 0x55555555;
int GLOBAL_B = 0x88888888;
int GLOBAL_C = 0x33333333;
char GLOBAL_D = 8;

struct Foo
{
  int a;
  char b[10];
};

int function1(int *n, char c __attribute__((unused)))
{
  return *n;
}

struct Foo *function2(struct Foo *foo1, struct Foo *foo2 __attribute__((unused)))
{
  return foo1;
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  usleep(1000000);

  int n = 13;
  char c = 'x';
  function1(&n, c);

  struct Foo foo1 = { .a = 123, .b = "hello" };
  struct Foo foo2 = { .a = 456, .b = "world" };
  function2(&foo1, &foo2);

  return 0;
}
