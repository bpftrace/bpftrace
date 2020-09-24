#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, logical_and_or_different_type)
{
  test("struct Foo { int m; }"
       "BEGIN"
       "{"
       "  $foo = *(struct Foo*)arg0;"
       "  printf(\"%d %d %d %d\", $foo.m && 0, 1 && $foo.m, $foo.m || 0, 0 || "
       "$foo.m)"
       "}",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
