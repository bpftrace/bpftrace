#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_signal)
{
  test("k:f { signal(arg0); }", NAME, false);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
