#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct Foo
{
  char* a;
  char b[4];
  uint8_t c[4];
  int d[4];
  uint16_t e[4];
  uint64_t f[4];
};

void func(struct Foo* foo)
{
  (void)foo;
}

int main()
{
  struct Foo foo = { .a = malloc(4),
                     .b = { 5, 4, 3, 2 },
                     .c = { 1, 2, 3, 4 },
                     .d = { 5, 6, 7, 8 },
                     .e = { 9, 10, 11, 12 },
                     .f = { 13, 14, 15, 16 } };
  strcpy(foo.a, "\x09\x08\x07\x06");
  func(&foo);
  free(foo.a);
  return 0;
}
