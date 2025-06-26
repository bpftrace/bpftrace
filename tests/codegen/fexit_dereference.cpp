#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, fexit_dereference)
{
  test("fexit:sk_alloc { @[retval->__sk_common.skc_daddr] = 1; }", NAME);
}

} // namespace bpftrace::test::codegen
