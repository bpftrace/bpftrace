#include <stdio.h>

#ifdef HAVE_SYSTEMTAP_SYS_SDT_H
#include <sys/sdt.h>
#else
#define DTRACE_PROBE1(a, b, c) (void)0
#endif

int main()
{
  int a = 1;
  // For some reason some compilers think `a` is unused
  (void)a;

  while (1)
    DTRACE_PROBE1(test, "probe1", a);

  return 0;
}
