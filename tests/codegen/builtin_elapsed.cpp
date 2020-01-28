#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_elapsed)
{
  test("i:s:1 { @ = elapsed; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
