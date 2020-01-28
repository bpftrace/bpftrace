#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_signal_string_literal)
{
  test("k:f { signal(\"SIGKILL\"); }", NAME, false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
