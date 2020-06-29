#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_print_non_map)
{
  test(R"_(k:f { print(3) })_",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
