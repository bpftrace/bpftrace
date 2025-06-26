#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, fentry_dereference)
{
  test("fentry:tcp_sendmsg { @[args->sk->__sk_common.skc_daddr] = 1; }", NAME);
}

} // namespace bpftrace::test::codegen
