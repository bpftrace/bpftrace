#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_offsetof)
{
  test("struct Foo { int x; long l; char c; }"
       "BEGIN { @x = offsetof(struct Foo, x); exit(); }",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
