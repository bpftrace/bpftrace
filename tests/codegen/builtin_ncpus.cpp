#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_ncpus)
{
  test("BEGIN { @x = ncpus; exit(); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
