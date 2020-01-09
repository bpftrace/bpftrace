#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline)) void increment(__attribute__((unused)) int _, int *i)
{
  (*i)++;
}

int main()
{
  int *i = malloc(sizeof(int));
  while (1)
  {
    increment(0, i);
    (*i)++;
    usleep(1000);
  }
}
