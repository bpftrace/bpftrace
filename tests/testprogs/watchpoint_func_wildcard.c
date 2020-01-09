#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define GEN_FUNC(x)                                                            \
  __attribute__((noinline)) void increment_##x(int *i)                         \
  {                                                                            \
    (*i)++;                                                                    \
  }

#define CALL_FUNC(x) increment_##x(malloc(sizeof(int)))

GEN_FUNC(0)
GEN_FUNC(1)
GEN_FUNC(2)
GEN_FUNC(3)
GEN_FUNC(4)
GEN_FUNC(5)
GEN_FUNC(6)
GEN_FUNC(7)
GEN_FUNC(8)
GEN_FUNC(9)
GEN_FUNC(10)
GEN_FUNC(11)
GEN_FUNC(12)
GEN_FUNC(13)
GEN_FUNC(14)
GEN_FUNC(15)
GEN_FUNC(16)
GEN_FUNC(17)
GEN_FUNC(18)
GEN_FUNC(19)
GEN_FUNC(20)

int main()
{
  CALL_FUNC(0);
  CALL_FUNC(1);
  CALL_FUNC(2);
  CALL_FUNC(3);
  CALL_FUNC(4);
  CALL_FUNC(5);
  CALL_FUNC(6);
  CALL_FUNC(7);
  CALL_FUNC(8);
  CALL_FUNC(9);
  CALL_FUNC(10);
  CALL_FUNC(11);
  CALL_FUNC(12);
  CALL_FUNC(13);
  CALL_FUNC(14);
  CALL_FUNC(15);
  CALL_FUNC(16);
  CALL_FUNC(17);
  CALL_FUNC(18);
  CALL_FUNC(19);
  CALL_FUNC(20);
}
