#include <unistd.h>

int included_entry(int x);
int wrapper_entry(int x);

int main(void)
{
  while (1) {
    wrapper_entry(1);
    included_entry(1);
    usleep(100000);
  }

  return 0;
}
