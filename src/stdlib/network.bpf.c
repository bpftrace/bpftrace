#include <stddef.h>

static int8_t as_char(int8_t v)
{
  if (v >= 0 && v <= 9) {
    return '0' + v;
  } else {
    return 'A' + (v - 10);
  }
}

void __macaddr(int8_t *dst, void *src)
{
  for (int i = 0; i < 6; i++) {
    int8_t b = ((int8_t *)src)[i];
    dst[3 * i] = as_char((b & 0xf0) >> 8);
    dst[(3 * i) + 1] = as_char(b & 0xf);
    if (i < 5) {
      dst[(3 * i) + 2] = (int8_t)':';
    }
  }
}
