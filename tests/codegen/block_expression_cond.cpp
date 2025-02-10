#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, block_expression_cond)
{
  test("kprobe:f { if ({ let $a = true; $a }) { exit() } }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
