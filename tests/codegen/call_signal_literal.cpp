#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_signal_literal)
{
  test("k:f { signal(8); }", NAME, false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
