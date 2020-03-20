#ifdef HAVE_SYSTEMTAP_SYS_SDT_H
#include <sys/sdt.h>
#else
#define DTRACE_PROBE1(a, b, c) (void)0
#endif
#include <stdint.h>

int main()
{
  uint32_t a = 0xdeadbeef;
  uint32_t b = 1;
  uint64_t c = UINT64_MAX;
  (void)a;
  (void)b;
  (void)c;

  while (1)
  {
    DTRACE_PROBE1(test, probe1, a);
    DTRACE_PROBE1(test, probe2, b);
    DTRACE_PROBE1(test, probe3, c);
  }

  return 0;
}
