#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, for_map_one_key)
{
  test("BEGIN { @map[16] = 32; for ($kv : @map) { @x = $kv; } }", NAME);
}

} // namespace bpftrace::test::codegen
