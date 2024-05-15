#include <stdint.h>

int fn(uint16_t nums[])
{
  return nums[0] + nums[1];
}

int main()
{
  uint16_t nums[] = {
    0x123, 0x456, 0x789, 0xabc, 0xdef, 0xcba,
  };
  fn(nums);
  return 0;
}
