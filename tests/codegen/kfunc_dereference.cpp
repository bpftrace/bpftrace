#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, kfunc_dereference)
{
  test("kfunc:tcp_sendmsg { @[args->sk->__sk_common.skc_daddr] = 1; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
