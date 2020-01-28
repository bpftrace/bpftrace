#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_max)
{
  test("kprobe:f { @x = max(pid) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
