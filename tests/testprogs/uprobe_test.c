#include <unistd.h>

int function1()
{
  return 0;
}

int main(int argc, char **argv) {
  usleep(1000000);
  return function1();
}
