#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, optional_positional_parameter)
{
  test("BEGIN { @x = $1; @y = str($2) }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
