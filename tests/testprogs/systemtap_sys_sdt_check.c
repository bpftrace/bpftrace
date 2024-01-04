int main()
{
  // If we don't have Systemtap headers, we should skip USDT tests. Returning 1
  // can be used as validation in the REQUIRE
#ifndef HAVE_SYSTEMTAP_SYS_SDT_H
  return 1;
#else
  return 0;
#endif
}
