#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#define _SDT_HAS_SEMAPHORES 1

#include "sdt.h"

__extension__ unsigned short tracetest_testprobe_semaphore
    __attribute__((unused)) __attribute__((section(".probes")))
    __attribute__((visibility("hidden")));

static long myclock()
{
  char buffer[100];
  struct timeval tv;
  gettimeofday(&tv, NULL);
  sprintf(buffer,
          "tracetest_testprobe_semaphore: %d\n",
          tracetest_testprobe_semaphore);
  DTRACE_PROBE2(tracetest, testprobe, tv.tv_sec, buffer);
  return tv.tv_sec;
}

int main()
{
  while (1) {
    myclock();
    // Sleep is necessary to not overflow perf buffer
    usleep(1000);
  }
  return 0;
}
