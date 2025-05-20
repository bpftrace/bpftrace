#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

// This function will be injected into all relevant probes.
//
// Note that this is not using the function `bpf_current_task_under_cgroup`,
// which would be convenient but requires quite a lot of extra plumbing (since
// it uses a BPF_MAP_TYPE_CGROUP_ARRAY map). In the future, we could easily
// support the equivalent semantics (checking for hierarchical membership) but
// plumbing the ancestor level to this pass and simply uses
// `bpf_get_current_ancestor_cgroup_id`.
int __in_cgroup(uint64_t cgroup_id)
{
  return bpf_get_current_cgroup_id() == cgroup_id;
}
