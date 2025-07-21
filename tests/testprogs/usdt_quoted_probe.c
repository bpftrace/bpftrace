#include "sdt.h"

int main()
{
  int a = 1;
  // For some reason some compilers think `a` is unused
  (void)a;

  while (1)
    DTRACE_PROBE1(test, "probe1", a);

  return 0;
}
