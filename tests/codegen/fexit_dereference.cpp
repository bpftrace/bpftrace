#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, fexit_dereference)
{
  test("fexit:sk_alloc { @[retval->__sk_common.skc_daddr] = 1; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
