#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "sdt.h"

static long myclock()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  DTRACE_PROBE2(tracetest, testprobe, tv.tv_sec, "Hello world");
  DTRACE_PROBE2(tracetest, testprobe2, tv.tv_sec, "Hello world2");
  DTRACE_PROBE2(tracetest2, testprobe2, tv.tv_sec, "Hello world3");
  return tv.tv_sec;
}

int main()
{
  while (1) {
    myclock();
  }
  return 0;
}
