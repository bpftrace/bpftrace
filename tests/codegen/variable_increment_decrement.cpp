#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, variable_increment_decrement)
{
  test("BEGIN { $x = 10; printf(\"%d\", $x++); printf(\"%d\", ++$x); "
       "printf(\"%d\", $x--); printf(\"%d\", --$x); }",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
