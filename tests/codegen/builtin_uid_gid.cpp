#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_uid_gid)
{
  test("kprobe:f { @x = uid; @y = gid }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
