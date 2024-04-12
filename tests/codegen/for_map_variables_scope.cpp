#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, for_map_variables_scope)
{
  // This test is to ensure that if variables are defined with the same name
  // in different loops, then they are each given their own stack allocations
  // and are not mixed up. Once we have proper variable scoping (#3017), the
  // special casing for for-loop codegen can go and this test can be removed.
  test("BEGIN { @map[16] = 32;\n"
       "for ($kv : @map) { $var = 1; }\n"
       "for ($kv : @map) { $var = 1; } }",
       NAME);
}

} // namespace bpftrace::test::codegen
