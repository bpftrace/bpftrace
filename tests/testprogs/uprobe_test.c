#include <unistd.h>

int GLOBAL_A = 0x55555555;
int GLOBAL_B = 0x88888888;
int GLOBAL_C = 0x33333333;
char GLOBAL_D = 8;

int function1()
{
  return 0;
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused))) {
  usleep(1000000);
  function1();
  return 0;
}
