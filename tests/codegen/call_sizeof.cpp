#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_sizeof)
{
  test("struct Foo { int x; char c; } BEGIN { @x = sizeof(struct Foo) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
