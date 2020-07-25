#include <stdint.h>
#include <stdio.h>

struct T
{
  uint32_t a;
  uint32_t b;
};

struct W
{
  uint32_t a;
  struct T t;
};

struct C
{
  uint32_t a;
  void* b;
  struct W w[10];
};

void clear(struct C* c)
{
  for (int x = 0; x < 10; x++)
  {
    c->w[x].t.a = 0;
  }
}

int main()
{
  struct C c;

  c.a = 0x55555555;
  c.b = (void*)0x55555555;
  for (int x = 0; x < 10; x++)
  {
    c.w[x].a = 100 + x;
    c.w[x].t.a = x;
    c.w[x].t.b = 100 - x;
  }

  clear(&c);
}
