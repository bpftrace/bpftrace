#include "usdt_tp.h"
#include <stdio.h>

int main(int argc, char **argv __attribute__((unused)))
{
  if (argc > 1)
  // If we don't have Systemtap headers, we should skip USDT tests. Returning 1
  // can be used as validation in the REQUIRE
#ifndef HAVE_SYSTEMTAP_SYS_SDT_H
    return 1;
#else
    return 0;
#endif

  while (1)
  {
    myclock();
  }
  return 0;
}
