#include "../mocks.h"
#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

using ::testing::Return;

TEST(codegen, builtin_func_wild)
{
  auto bpftrace = get_mock_bpftrace();

  test(*bpftrace,
       "kprobe:do_execve* { @x = func }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
