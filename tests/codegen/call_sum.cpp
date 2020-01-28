#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_sum)
{
  test("kprobe:f { @x = sum(pid) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
