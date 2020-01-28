#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, map_key_string)
{
  test("kprobe:f { @x[\"a\", \"b\"] = 44 }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
