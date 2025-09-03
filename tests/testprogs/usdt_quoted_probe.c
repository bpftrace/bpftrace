#include "libbpf-usdt/usdt.h"

int main()
{
  int a = 1;
  // For some reason some compilers think `a` is unused
  (void)a;

  while (1)
    USDT(test, "probe1", a);

  return 0;
}
