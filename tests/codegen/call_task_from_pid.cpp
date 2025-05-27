#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_task_from_pid)
{
  test("tracepoint:syscalls:sys_enter_kill {"
       " $task = task_from_pid(1);"
       " if ($task) { task_release($task); }"
       " exit();"
       "}",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
