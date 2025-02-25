#include "../mocks.h"
#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, strcontains)
{
  test(R"(k:foo { strcontains("hello-test-world", "test") })", NAME);
}

TEST(codegen, strcontains_one_literal)
{
  test(R"(k:foo { strcontains(str(arg0), "test") })", NAME);
}

TEST(codegen, strcontains_no_literals)
{
  test(R"(k:foo { strcontains(str(arg0), str(arg1)) })", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
