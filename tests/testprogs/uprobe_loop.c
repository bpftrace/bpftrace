#include <unistd.h>

int uprobeFunction1(int *n, char c __attribute__((unused)))
{
  return *n;
}

void spin()
{
  while (1) {
    int n = 13;
    char c = 'x';
    uprobeFunction1(&n, c);
    usleep(500);
  }
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  spin();
  return 0;
}
