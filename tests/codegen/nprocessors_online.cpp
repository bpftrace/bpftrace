#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, nprocessors_online)
{
  test("BEGIN { @x = nproc; exit(); }",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
