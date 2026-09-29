#include "bpf_iters.h"

#include <algorithm>

namespace bpftrace {

const std::vector<BpfIterItem> BPF_ITER_LIST = {
  // BPF_TASK_ITER_ALL_PROCS
  { .name = "iter_task",
    .kfunc = "bpf_iter_task",
    .yields = "struct task_struct",
    .min_args = 0,
    .max_args = 0,
    .flags = 0 },
  // BPF_TASK_ITER_ALL_THREADS
  { .name = "iter_threads",
    .kfunc = "bpf_iter_task",
    .yields = "struct task_struct",
    .min_args = 0,
    .max_args = 0,
    .flags = 1 },
  // BPF_TASK_ITER_PROC_THREADS
  { .name = "iter_task_threads",
    .kfunc = "bpf_iter_task",
    .yields = "struct task_struct",
    .min_args = 1,
    .max_args = 1,
    .flags = 2 },
  { .name = "iter_task_vma",
    .kfunc = "bpf_iter_task_vma",
    .yields = "struct vm_area_struct",
    .min_args = 1,
    .max_args = 2,
    .flags = std::nullopt },
};

const BpfIterItem *find_bpf_iter(std::string_view name)
{
  auto it = std::ranges::find(BPF_ITER_LIST, name, &BpfIterItem::name);
  if (it == BPF_ITER_LIST.end()) {
    return nullptr;
  }
  return &*it;
}

} // namespace bpftrace
