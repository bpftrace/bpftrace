#define _SDT_HAS_SEMAPHORES 1

#ifdef HAVE_SYSTEMTAP_SYS_SDT_H
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(a, b, c, d) (void)0
#endif
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

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
