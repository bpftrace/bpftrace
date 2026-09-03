#define __KERNEL__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// __always_true is a built-in test function to validate C interop is working
// as expected.
int __always_true() { return 1; }

// __test_get_current_task is a built-in test function to validate that a
// pointer to a named struct can be returned across the C interop boundary.
struct task_struct *__test_get_current_task() {
  return bpf_get_current_task_btf();
}
