#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

class MockBPFtraceCpid : public BPFtrace
{
public:
  MOCK_METHOD0(child_pid, int(void));
};

TEST(codegen, builtin_cpid)
{
  MockBPFtraceCpid bpftrace;
  bpftrace.cmd_ = "sleep 1";
  ON_CALL(bpftrace, child_pid()).WillByDefault(Return(1337));

  test(bpftrace,
       "kprobe:f { @ = cpid }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
