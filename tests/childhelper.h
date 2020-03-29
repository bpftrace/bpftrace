#include <time.h>

#include "child.h"
#include "utils.h"

namespace bpftrace {
namespace test {

static int msleep(int msec)
{
  struct timespec sleep = { .tv_sec = 0, .tv_nsec = msec * 1000000L };
  struct timespec rem = {};
  if (nanosleep(&sleep, &rem) < 0)
    return 1000L * rem.tv_sec + 1000000L * rem.tv_nsec;
  return 0;
}

static void wait_for(ChildProcBase *child, int msec_timeout)
{
  constexpr int wait = 10;
  while (child->is_alive() && msec_timeout > 0)
    msec_timeout -= wait - msleep(wait);
}

static std::unique_ptr<ChildProc> getChild(std::string cmd)
{
  std::unique_ptr<ChildProc> child;
  {
    StderrSilencer es;
    StdoutSilencer os;
    os.silence();
    es.silence();
    child = std::make_unique<ChildProc>(cmd);
  }
  EXPECT_NE(child->pid(), -1);
  EXPECT_TRUE(child->is_alive());
  return child;
}

} // namespace test
} // namespace bpftrace
