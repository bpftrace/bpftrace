#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline)) void increment(int *i)
{
  (*i)++;
}

int main()
{
  int *i = malloc(sizeof(int));
  increment(i);

  // Yes, this sleep sucks but unwatch is async and we have
  // no way to delay the bpf prog
  sleep(1);

  (*i)++;
  (*i)++;
  (*i)++;
  (*i)++;
}
