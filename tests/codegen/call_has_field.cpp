#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_has_field)
{
  test("struct Foo { int x; char c; } BEGIN { @x = has_field(struct Foo,
       \"x\") }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
