#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, ptr_to_ptr)
{
  test(
      R"PROG(kprobe:f { $pp = (int32 **)0; printf("%d\n", **kptr($pp)); })PROG",

      NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
