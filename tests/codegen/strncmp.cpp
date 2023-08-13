#include "../mocks.h"
#include "common.h"

using ::testing::_;
using ::testing::Return;

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, strncmp)
{
  test("t:file:filename /str(args.filename) == comm/ { @=1 }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
