#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bpftrace {

enum class TaskIterFlags : uint32_t {
  all_procs = 0,
  all_threads = 1,
  proc_threads = 2,
};

struct BpfIterItem {
  std::string name;
  std::string kfunc;
  size_t iter_size;
  std::string yields;
  std::optional<TaskIterFlags> flags;
};

extern const std::vector<BpfIterItem> BPF_ITER_LIST;

const BpfIterItem *find_bpf_iter(std::string_view name);

} // namespace bpftrace
