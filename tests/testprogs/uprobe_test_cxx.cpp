#include <unistd.h>

struct Foo {
  int a, b, c;
  int &x;
};

class Bar {
public:
  int x, y, z;
};

int uprobeFunction1(int &x, Foo &foo, Bar &bar __attribute__((unused)))
{
  return x + foo.c;
}

int uprobeArray(int (&array)[10])
{
  return array[0];
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  int x = 42;
  Foo foo{ 1, 2, 3, x };
  Bar bar{ 10, 11, 12 };
  uprobeFunction1(x, foo, bar);

  int arr[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
  uprobeArray(arr);

  return 0;
}
