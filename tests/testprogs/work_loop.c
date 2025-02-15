#include <unistd.h>

int doWork(int *n, int o)
{
  return *n += o;
}

void spin()
{
  int i = 0;
  while (1) {
    int n = 1;
    doWork(&n, i);
    usleep(10);
    ++i;
  }
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  spin();
  return 0;
}
