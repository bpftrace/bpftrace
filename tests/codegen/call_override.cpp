#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_override)
{
  test("kprobe:f { override(arg0); }", NAME, false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
