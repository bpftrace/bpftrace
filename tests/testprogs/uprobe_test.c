#include <unistd.h>

int GLOBAL_A = 0x55555555;
int GLOBAL_B = 0x88888888;
int GLOBAL_C = 0x33333333;
char GLOBAL_D = 8;

struct Foo {
  int a;
  char b[10];
  int c[3];
  __int128_t d;
};

int uprobeFunction1(int *n, char c __attribute__((unused)))
{
  return *n;
}

struct Foo *uprobeFunction2(struct Foo *foo1,
                            struct Foo *foo2 __attribute__((unused)))
{
  return foo1;
}

// clang-format off
/*
 * Anonymous types inside parameter lists are not legal until C23 [0][1][2].
 * On a non-C23 build, we get unsilencable compiler warnings:
 *
 *     /home/dxu/dev/bpftrace/tests/testprogs/uprobe_test.c:26:10: warning: anonymous enum declared inside parameter list will not be visible outside of this definition or declaration
 *        26 |     enum { A, B, C } e,
 *           |          ^
 *     [4/5] Linking C executable tests/testprogs/uprobe_test
 *
 * So for now, leave this commented out until C23 is more widely available.
 *
 * [0]: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108189
 * [1]: https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3037.pdf
 * [2]: https://www.reddit.com/r/C_Programming/comments/w5hl80/comment/ih8jxi6/?context=3
 *
 * int uprobeFunction3(
 *     enum { A, B, C } e,
 *     union {
 *       int a;
 *       char b;
 *     } u __attribute__((unused)))
 * {
 *   return e;
 * }
 */
// clang-format on

__uint128_t uprobeFunctionUint128(__uint128_t x,
                                  __uint128_t y __attribute__((unused)),
                                  __uint128_t z __attribute__((unused)),
                                  __uint128_t w)
{
  return x + w;
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  usleep(1000000);

  int n = 13;
  char c = 'x';
  uprobeFunction1(&n, c);

  struct Foo foo1 = {
    .a = 123, .b = "hello", .c = { 1, 2, 3 }, .d = 0x123456789ABCDEF0
  };
  struct Foo foo2 = {
    .a = 456, .b = "world", .c = { 4, 5, 6 }, .d = 0xFEDCBA9876543210
  };
  uprobeFunction2(&foo1, &foo2);

  __uint128_t x = 0x123456789ABCDEF0;
  __uint128_t y = 0xEFEFEFEFEFEFEFEF;
  __uint128_t z = 0xCDCDCDCDCDCDCDCD;
  __uint128_t w = 0xABABABABABABABAB;
  uprobeFunctionUint128(x, y, z, w);

  return 0;
}
