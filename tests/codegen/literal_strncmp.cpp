#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, literal_strncmp)
{
  test("kretprobe:vfs_read /strncmp(comm, \"sshd\", 2)/ { @[comm] = count(); }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
