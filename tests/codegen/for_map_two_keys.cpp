#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, for_map_two_keys)
{
  test("BEGIN { @map[16,17] = 32; for ($kv : @map) { @x = $kv; } }", NAME);
}

} // namespace bpftrace::test::codegen
