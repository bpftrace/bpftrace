#include <stdio.h>

#ifdef HAVE_SYSTEMTAP_SYS_SDT_H
#include <sys/sdt.h>
#else
#define DTRACE_PROBE1(a, b, c) (void)0
#endif

int main(int argc, char **argv __attribute__((unused)))
{
  if (argc > 1)
  // If we don't have Systemtap headers, we should skip USDT tests. Returning 1
  // can be used as validation in the REQUIRE
#ifndef HAVE_SYSTEMTAP_SYS_SDT_H
    return 1;
#else
    return 0;
#endif

  int a = 1;
  // For some reason some compilers think `a` is unused
  (void)a;

  while (1)
    DTRACE_PROBE1(test, "probe1", a);

  return 0;
}
