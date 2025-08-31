#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "libbpf-usdt/usdt.h"

__attribute__((always_inline)) inline static void myclock(int probe_num)
{
  // Volatile forces reading directly from the stack so that
  // the probe's argument is not saved as a constant value.
  volatile int on_stack = probe_num;
  (void)on_stack;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  USDT(tracetest, testprobe, tv.tv_sec, on_stack);
}

__attribute__((always_inline)) inline static void mywrapper_inlined() {
  myclock(100);
}

static void mywrapper()
{
  mywrapper_inlined();
}

static void loop()
{
  while (1) {
    myclock(999);
    mywrapper();
    sleep(1);
  }
}

int main()
{
  loop();

  return 0;
}
