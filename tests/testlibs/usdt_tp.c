#include "usdt_tp.h"

#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "libbpf-usdt/usdt.h"

long myclock()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  USDT(tracetestlib, lib_probe_1, tv.tv_sec, "Hello world");
  USDT(tracetestlib, lib_probe_1, tv.tv_sec, "Hello world2");
  USDT(tracetestlib2, lib_probe_2, tv.tv_sec, "Hello world3");
  return tv.tv_sec;
}
