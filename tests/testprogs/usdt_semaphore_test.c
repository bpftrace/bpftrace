#define _SDT_HAS_SEMAPHORES 1

#ifdef HAVE_SYSTEMTAP_SYS_SDT_H
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(a, b, c, d) (void)0
#endif
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>

__extension__ unsigned short tracetest_testprobe_semaphore __attribute__ ((unused)) __attribute__ ((section (".probes"))) __attribute__ ((visibility ("hidden")));

static long
myclock() {
  char buffer[100];
  struct timeval tv;
  gettimeofday(&tv, NULL);
  sprintf(buffer, "tracetest_testprobe_semaphore: %d\n", tracetest_testprobe_semaphore);
  DTRACE_PROBE2(tracetest,  testprobe,  tv.tv_sec, buffer);
  return tv.tv_sec;
}

int
main(int argc, char **argv __attribute__((unused))) {
  if (argc > 1)
  // If we don't have Systemtap headers, we should skip USDT tests. Returning 1 can be used as validation in the REQUIRE
#ifndef HAVE_SYSTEMTAP_SYS_SDT_H
    return 1;
#else
    return 0;
#endif

  while (1) {
    myclock();
    // Sleep is necessary to not overflow perf buffer
    usleep(1000);
  }
  return 0;
}
