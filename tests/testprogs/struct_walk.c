#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct C
{
  uint32_t a;
  uint64_t b;
};

void clear(struct C* c, size_t size)
{
  for (size_t t = 0; t < size; t++)
  {
    c[t].a = 0;
    c[t].b = 0;
  }
}

void print(struct C* c, size_t size)
{
  uint32_t sum = 0;
  while (size--)
    sum += (c++)->a;
  printf("Sum: %u\n", sum);
}

int main()
{
  size_t size = 10;
  struct C* c = (struct C*)malloc(sizeof(struct C) * size);

  for (size_t t = 0; t < size; t++)
  {
    c[t].a = t;
    c[t].b = 100;
  }

  clear(c, size);
}
