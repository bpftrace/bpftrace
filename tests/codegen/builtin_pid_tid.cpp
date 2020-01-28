#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_pid_tid)
{
  test("kprobe:f { @x = pid; @y = tid }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
