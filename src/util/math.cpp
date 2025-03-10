#include <cassert>

#include "util/math.h"

namespace bpftrace::util {

uint32_t round_up_to_next_power_of_two(uint32_t n)
{
  // http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
  if (n == 0) {
    return 0;
  }
  // Note this function doesn't work if n > 2^31 since there are not enough
  // bits in unsigned 32 bit integers. This should be fine since its unlikely
  // anyone has > 2^31 CPUs.
  assert(n <= 2147483648);
  n--;
  n |= n >> 1;
  n |= n >> 2;
  n |= n >> 4;
  n |= n >> 8;
  n |= n >> 16;
  return n + 1;
}

} // namespace bpftrace::util
