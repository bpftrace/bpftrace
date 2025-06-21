#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, getopt)
{
  test("kprobe:f { $x = getopt(\"hello\", 1); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
