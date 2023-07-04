#include <unistd.h>

int function1(int *n)
{
  return *n;
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  int n = 0;
  while (1) {
    usleep(1000000);
    n += function1(&n);
  }

  return 0;
}
