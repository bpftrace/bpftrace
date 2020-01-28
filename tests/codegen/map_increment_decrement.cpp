#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, map_increment_decrement)
{
  test("BEGIN { @x = 10; @x++; ++@x; @x--; --@x; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
