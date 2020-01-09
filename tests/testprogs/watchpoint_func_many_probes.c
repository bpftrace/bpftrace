#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline)) void increment(int *i)
{
  (*i)++;
}

int main()
{
  for (int i = 0; i < 20; ++i)
  {
    increment(malloc(sizeof(int)));
  }
}
