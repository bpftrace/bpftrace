#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, tuple)
{
  test(R"_(k:f { @t = (1, 2, "str"); })_",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
