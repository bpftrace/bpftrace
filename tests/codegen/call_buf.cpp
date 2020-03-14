#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_buf_implicit_size)
{
  test("struct x { int c[4] }; kprobe:f { $foo = (struct x*)0; @x = "
       "buf($foo->c); }",

       NAME);
}

TEST(codegen, call_buf_size_literal)
{
  test("kprobe:f { @x = buf(arg0, 1) }",

       NAME);
}

TEST(codegen, call_buf_size_nonliteral)
{
  test("kprobe:f { @x = buf(arg0, arg1) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
