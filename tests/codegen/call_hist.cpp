#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_hist)
{
  test("kprobe:f { @x = hist(pid) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
