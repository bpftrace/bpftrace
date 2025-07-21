#include "usdt_tp.h"

#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "sdt.h"

long myclock()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  DTRACE_PROBE2(tracetestlib, lib_probe_1, tv.tv_sec, "Hello world");
  DTRACE_PROBE2(tracetestlib, lib_probe_1, tv.tv_sec, "Hello world2");
  DTRACE_PROBE2(tracetestlib2, lib_probe_2, tv.tv_sec, "Hello world3");
  return tv.tv_sec;
}
