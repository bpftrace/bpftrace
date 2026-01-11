#define __KERNEL__
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

struct task_struct* __get_current_task() {
  return (struct task_struct *)bpf_get_current_task_btf();
}
