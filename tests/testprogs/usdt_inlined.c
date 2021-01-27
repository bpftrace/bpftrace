#ifdef HAVE_SYSTEMTAP_SYS_SDT_H
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(a, b, c, d) (void)0
#endif
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

__attribute__((always_inline)) inline static void myclock(int probe_num)
{
  // Volatile forces reading directly from the stack so that
  // the probe's argument is not saved as a constant value.
  volatile int on_stack = probe_num;
  (void)on_stack;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  DTRACE_PROBE2(tracetest, testprobe, tv.tv_sec, on_stack);
}

static void mywrapper()
{
  myclock(100);
}

static void loop()
{
  while (1)
  {
    myclock(999);
    mywrapper();
    sleep(1);
  }
}

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

  loop();

  return 0;
}
