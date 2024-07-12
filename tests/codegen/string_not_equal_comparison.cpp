#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, string_not_equal_comparison)
{
  test("kprobe:f { @[comm != \"sshd\"] = 1; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
