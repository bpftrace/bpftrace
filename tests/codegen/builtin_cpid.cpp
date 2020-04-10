#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

class MockBPFtraceCpid : public BPFtrace
{
  pid_t child_pid()
  {
    return 1337;
  };
};

TEST(codegen, builtin_cpid)
{
  MockBPFtraceCpid bpftrace;
  bpftrace.cmd_ = "sleep 1";

  test(bpftrace,
       "kprobe:f { @ = cpid }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
