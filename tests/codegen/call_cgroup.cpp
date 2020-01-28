#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_cgroup)
{
  test("tracepoint:syscalls:sys_enter_openat /cgroup == 0x100000001/ { @x = "
       "cgroup }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
