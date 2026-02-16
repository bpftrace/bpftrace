#define __KERNEL__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

extern struct task_struct *bpf_task_from_pid(s32 pid) __weak __ksym;
extern void bpf_task_release(struct task_struct *p) __weak __ksym;

typedef char comm_str[16];

int __bpf_task_comm_from_pid(s32 pid, comm_str *out) {
  if (!bpf_task_from_pid || !bpf_task_release)
    return -95; // EOPNOTSUPP: Operation not supported

  struct task_struct *task = bpf_task_from_pid(pid);
  if (task) {
    __builtin_memcpy(out, &task->comm, sizeof(*out));
    bpf_task_release(task);
    return 0;
  }
  return -3; // ESRCH: No such process
}
