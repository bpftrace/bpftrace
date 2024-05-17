#include <stdio.h>

/* always_inline instructs the compiler to inline the function, even in -O0.
 * used instructs the compiler to keep the function in the final binary.
 * Using both attribute at the same time enable testing both regular and
 * inlined call to the square function. The first two calls in main will be
 * inlined and the last call will be a regular call.
 */
__attribute__((always_inline, used)) static inline int square(int x)
{
  volatile int res = x * x;
  return res;
}

int main(int argc, char *argv[] __attribute__((unused)))
{
  printf("%d^2 = %d\n", argc, square(argc));

  printf("%d^2 = %d\n", 8, square(8));

  // Make a call to `square` through the `square_ptr` pointer,
  // to prevent the compiler from inlining the call
  int x = 10;
  int (*square_ptr)(int) = square;
  printf("%d^2 = %d\n", x, square_ptr(x));

  return 0;
}
