#define __KERNEL__
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

extern struct cgroup *bpf_cgroup_from_id(u64 cgid) __weak __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __weak __ksym;
extern long bpf_task_under_cgroup(struct task_struct *task, struct cgroup *ancestor) __weak __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __weak __ksym;

// Note that this is not using the function `bpf_current_task_under_cgroup`,
// which would be convenient but requires quite a lot of extra plumbing (since
// it uses a BPF_MAP_TYPE_CGROUP_ARRAY map). In the future, we could easily
// support the equivalent semantics (checking for hierarchical membership) but
// plumbing the ancestor level to this pass and simply uses
// `bpf_get_current_ancestor_cgroup_id`.
_Bool __in_cgroup(u64 cgroup_id)
{
  struct cgroup *grp = bpf_cgroup_from_id(cgroup_id);
  if (!grp) {
    return 0;
  }
  int rval = bpf_task_under_cgroup(bpf_get_current_task_btf(), grp);
  bpf_cgroup_release(grp);
  return rval == 1;
}
