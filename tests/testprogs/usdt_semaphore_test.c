#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "libbpf-usdt/usdt.h"

USDT_DEFINE_SEMA(tracetest_testprobe_semaphore);

static long myclock()
{
  char buffer[100];
  struct timeval tv;
  gettimeofday(&tv, NULL);
  if (USDT_SEMA_IS_ACTIVE(tracetest_testprobe_semaphore)) {
    snprintf(buffer,
             sizeof(buffer),
             "USDT semaphore: %d\n",
             USDT_SEMA(tracetest_testprobe_semaphore).active);
    USDT_WITH_EXPLICIT_SEMA(
        tracetest_testprobe_semaphore, tracetest, testprobe, tv.tv_sec, buffer);
  }
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
