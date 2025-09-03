#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "libbpf-usdt/usdt.h"

static long myclock()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  static volatile char str1[] = "Hello World1";
  static volatile char str2[] = "Hello World2";
  static volatile char str3[] = "Hello World3";
  USDT(tracetest, testprobe, tv.tv_sec, str1);
  USDT(tracetest, testprobe2, tv.tv_sec, str2);
  USDT(tracetest2, testprobe2, tv.tv_sec, str3);
  return tv.tv_sec;
}

int main()
{
  while (1) {
    myclock();
    // Reduce the frequency of events to reduce test flakyness
    usleep(100000);
  }
  return 0;
}
