#include <sys/time.h>
#include <unistd.h>

#include "libbpf-usdt/usdt.h"

static long myclock()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  USDT(tracetest, testprobe, tv.tv_sec, "Hello world");
  USDT(tracetest, testprobe, tv.tv_sec, "Hello world2");
  USDT(tracetest, testprobe2, tv.tv_sec, "Hello world3");
  USDT(tracetest, testprobe3, tv.tv_sec, "Hello world4");
  USDT(tracetest, testprobe3, tv.tv_sec, "Hello world5");
  USDT(tracetest, testprobe3, tv.tv_sec, "Hello world6");
  return tv.tv_sec;
}

int main()
{
  while (1) {
    myclock();
  }
  return 0;
}
