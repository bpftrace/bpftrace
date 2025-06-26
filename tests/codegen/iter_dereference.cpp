#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, iter_dereference)
{
  test("iter:task_file { @[ctx->meta->session_id] = 1; }", NAME);
}

} // namespace bpftrace::test::codegen
