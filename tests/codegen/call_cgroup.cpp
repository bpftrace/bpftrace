#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_cgroup)
{
  test("tracepoint:syscalls:sys_enter_openat /cgroup == 0x100000001/ { @x = "
       "cgroup }",

       NAME);
}

} // namespace bpftrace::test::codegen
