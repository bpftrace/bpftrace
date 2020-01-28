#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_min)
{
  test("kprobe:f { @x = min(pid) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
