#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_stats)
{
  test("kprobe:f { @x = stats(pid) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
