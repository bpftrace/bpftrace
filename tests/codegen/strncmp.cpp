#include "../mocks.h"
#include "common.h"

using ::testing::_;
using ::testing::Return;

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, strncmp_one_literal)
{
  test("kprobe:f { @[strncmp(comm, \"sshd\", 2)] = 1; }",

       NAME);
}

TEST(codegen, strncmp_no_literals)
{
  test("t:file:filename /str(args.filename) == comm/ { @=1 }", NAME);
}

TEST(codegen, string_equal_comparison)
{
  test("kprobe:f { @[comm == \"sshd\"] = 1; }",

       NAME);
}

TEST(codegen, string_not_equal_comparison)
{
  test("kprobe:f { @[comm != \"sshd\"] = 1; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
