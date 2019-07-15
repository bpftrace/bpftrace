#include <unistd.h>

int function1()
{
  return 0;
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused))) {
  while (1) {
    function1();
  }
  return 0;
}
