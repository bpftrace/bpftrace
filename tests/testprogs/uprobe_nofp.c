#include <unistd.h>

// This test program is compiled without frame pointers (-fomit-frame-pointer).
// Only DWARF-based stack unwinding can produce a full stack trace.

volatile int sink;

__attribute__((noinline)) void funcD(void)
{
  sink = 42;
}

__attribute__((noinline)) void funcC(void)
{
  funcD();
  sink;
}

__attribute__((noinline)) void funcB(void)
{
  funcC();
  sink;
}

__attribute__((noinline)) void funcA(void)
{
  funcB();
  sink;
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  while (1) {
    funcA();
    usleep(500);
  }
  return 0;
}
