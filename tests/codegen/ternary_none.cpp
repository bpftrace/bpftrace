#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, ternary_none)
{
  test("kprobe:f { pid < 10000 ? printf(\"hello\") : exit(); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
