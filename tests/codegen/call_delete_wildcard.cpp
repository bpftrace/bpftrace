#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_delete_wildcard)
{
  test("kprobe:f { @x[10, 10] = 1; delete(@x[*, 10]); }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
