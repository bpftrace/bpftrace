#include "../mocks.h"
#include "common.h"

using ::testing::_;
using ::testing::Return;

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, strncmp)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace,
       "t:file:filename /str(args->filename) == comm/ { @=1 }",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
