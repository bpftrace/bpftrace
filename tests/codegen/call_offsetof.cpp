#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_offsetof)
{
  test("struct Foo { int x; long l; char c; }"
       "begin { @x = offsetof(struct Foo, x); exit(); }",
       NAME);
}

TEST(codegen, call_offsetof_sub_field)
{
  test("struct Foo { struct Bar { int a; } d; }"
       "begin { @x = offsetof(struct Foo, d.a); exit(); }",
       NAME);
}

} // namespace bpftrace::test::codegen
