#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_socket_cookie)
{
  test("fentry:tcp_rcv_established { $ret = socket_cookie(args->sk); }", NAME);
}

} // namespace bpftrace::test::codegen
