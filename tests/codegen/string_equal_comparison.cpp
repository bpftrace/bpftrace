#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, string_equal_comparison)
{
  test("kretprobe:vfs_read /comm == \"sshd\"/ { @[comm] = count(); }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
