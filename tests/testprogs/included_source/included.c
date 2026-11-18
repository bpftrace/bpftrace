#ifndef ENTRY
#define ENTRY included_entry
#endif

static int helper(int x)
{
  return x * 3;
}

int ENTRY(int x)
{
  return helper(x) + 1;
}
