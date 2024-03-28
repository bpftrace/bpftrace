#include <unistd.h>

int GLOBAL_A = 0x55555555;
int GLOBAL_B = 0x88888888;
int GLOBAL_C = 0x33333333;
char GLOBAL_D = 8;

struct Foo {
  int a;
  char b[10];
  int c[3];
};

int uprobeFunction1(int *n, char c __attribute__((unused)))
{
  return *n;
}

struct Foo *uprobeFunction2(struct Foo *foo1,
                            struct Foo *foo2 __attribute__((unused)))
{
  return foo1;
}

int uprobeFunction3(
    enum { A, B, C } e,
    union {
      int a;
      char b;
    } u __attribute__((unused)))
{
  return e;
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  usleep(1000000);

  int n = 13;
  char c = 'x';
  uprobeFunction1(&n, c);

  struct Foo foo1 = { .a = 123, .b = "hello", .c = { 1, 2, 3 } };
  struct Foo foo2 = { .a = 456, .b = "world", .c = { 4, 5, 6 } };
  uprobeFunction2(&foo1, &foo2);

  return 0;
}
