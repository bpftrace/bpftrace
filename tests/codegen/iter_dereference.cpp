#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, iter_dereference)
{
  test("iter:task_file { @[ctx->meta->session_id] = count()}", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
