#include <stdint.h>

#include "libbpf-usdt/usdt.h"

int main()
{
  uint32_t a = 0xdeadbeef;
  uint32_t b = 1;
  uint64_t c = UINT64_MAX;
  uint32_t d = 0xcafebabe;
  uint32_t e = 0x8badf00d;
  uint32_t f = 0xfeedface;
  uint64_t g = 0x0123456789abcdefULL;
  uint64_t h = 0x0ULL;
  uint64_t i = 0x7fffffffffffffffULL;
  uint64_t j = 0x5555555555555555ULL;
  uint32_t k = 42;
  uint64_t l = 0xaaaaaaaaaaaaaaaaULL;

  while (1) {
    USDT(usdt_multi_args, probe1, a, b, c, d, e, f, g, h, i, j, k, l);
  }

  return 0;
}

