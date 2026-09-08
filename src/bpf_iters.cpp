#include "bpf_iters.h"

#include <algorithm>

namespace bpftrace {

const std::vector<BpfIterItem> BPF_ITER_LIST = {
  { .name = "iter_task",
    .kfunc = "bpf_iter_task",
    .iter_size = 24,
    .yields = "struct task_struct",
    .flags = TaskIterFlags::all_procs },
  { .name = "iter_threads",
    .kfunc = "bpf_iter_task",
    .iter_size = 24,
    .yields = "struct task_struct",
    .flags = TaskIterFlags::all_threads },
  { .name = "iter_task_threads",
    .kfunc = "bpf_iter_task",
    .iter_size = 24,
    .yields = "struct task_struct",
    .flags = TaskIterFlags::proc_threads },
  { .name = "iter_task_vma",
    .kfunc = "bpf_iter_task_vma",
    .iter_size = 8,
    .yields = "struct vm_area_struct",
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
