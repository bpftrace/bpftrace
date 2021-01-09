#ifdef HAVE_SYSTEMTAP_SYS_SDT_H
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(a, b, c, d) (void)0
#endif
#include <stdlib.h>
#include <string.h>

int main()
{
  const char *s = "hello";
  size_t s_len = strlen(s);
  (void)s;
  (void)s_len;

  while (1)
  {
    DTRACE_PROBE2(test, probe1, s, s_len);
    DTRACE_PROBE2(test, probe2, s, (int)s_len);
  }

  return 0;
}
