#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, multiple_identical_probes)
{
  test("kprobe:f { 1; } kprobe:f { 1; }",

       NAME);
}

} // namespace bpftrace::test::codegen
