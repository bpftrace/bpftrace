#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, empty_function)
{
  test("kprobe:f { 1; }",

       NAME);
}

} // namespace bpftrace::test::codegen
