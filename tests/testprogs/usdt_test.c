#ifdef HAVE_SYSTEMTAP_SYS_SDT_H
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(a, b, c, d) (void)0
#endif
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>

static long
myclock() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  DTRACE_PROBE2(tracetest,  testprobe,  tv.tv_sec, "Hello world");
  DTRACE_PROBE2(tracetest,  testprobe2, tv.tv_sec, "Hello world2");
  DTRACE_PROBE2(tracetest2, testprobe2, tv.tv_sec, "Hello world3");
  return tv.tv_sec;
}

int
main(int argc, char **argv) {
  if (argc > 1)
  // If we don't have Systemtap headers, we should skip USDT tests. Returning 1 can be used as validation in the REQUIRE
#ifndef HAVE_SYSTEMTAP_SYS_SDT_H
    return 1;
#else
    return 0;
#endif

  while (1) {
    myclock();
  }
  return 0;
}
