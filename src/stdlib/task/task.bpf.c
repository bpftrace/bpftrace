#define __KERNEL__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../strings/strings.h"

extern struct task_struct *bpf_task_from_pid(s32 pid) __weak __ksym;
extern void bpf_task_release(struct task_struct *p) __weak __ksym;

int __bpf_task_comm_from_pid(s32 pid, m_arg *out) {
  if (!bpf_task_from_pid || !bpf_task_release)
    return -95; // EOPNOTSUPP: Operation not supported

  struct task_struct *task = bpf_task_from_pid(pid);
  if (task) {
    __builtin_memcpy(&out->data, &task->comm, sizeof(*out));
    bpf_task_release(task);
    return 0;
  }
  return -3; // ESRCH: No such process
}
