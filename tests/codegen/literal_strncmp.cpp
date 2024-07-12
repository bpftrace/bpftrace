#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, literal_strncmp)
{
  test("kprobe:f { @[strncmp(comm, \"sshd\", 2)] = 1; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
