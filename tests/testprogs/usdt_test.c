#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "sdt.h"

static long myclock()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  static volatile char str1[] = "Hello World1";
  static volatile char str2[] = "Hello World2";
  static volatile char str3[] = "Hello World3";
  DTRACE_PROBE2(tracetest, testprobe, tv.tv_sec, str1);
  DTRACE_PROBE2(tracetest, testprobe2, tv.tv_sec, str2);
  DTRACE_PROBE2(tracetest2, testprobe2, tv.tv_sec, str3);
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
