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

TEST(codegen, call_offsetof_sub_field)
{
  test("struct Foo { struct Bar { int a; } d; }"
       "BEGIN { @x = offsetof(struct Foo, d.a); exit(); }",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
