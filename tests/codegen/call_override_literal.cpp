#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_override_literal)
{
  test("kprobe:f { override(-1); }", NAME, false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
