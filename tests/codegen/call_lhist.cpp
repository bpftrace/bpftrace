#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_lhist)
{
  test("kprobe:f { @x = lhist(pid, 0, 100, 1) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
