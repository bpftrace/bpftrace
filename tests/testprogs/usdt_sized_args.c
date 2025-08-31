#include <stdint.h>

#include "libbpf-usdt/usdt.h"

int main()
{
  uint32_t a = 0xdeadbeef;
  uint32_t b = 1;
  uint64_t c = UINT64_MAX;
  (void)a;
  (void)b;
  (void)c;

  while (1) {
    USDT(test, probe1, a);
    USDT(test, probe2, b);
    USDT(test, probe3, c);
  }

  return 0;
}
