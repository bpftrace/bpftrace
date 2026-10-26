#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "types.h"

namespace bpftrace {

struct BpfIterItem {
  std::string name;
  std::string kfunc;
  std::string yields;
  size_t min_args;
  size_t max_args;
  std::optional<uint64_t> flags;
};

extern const std::vector<BpfIterItem> BPF_ITER_LIST;

const BpfIterItem *find_bpf_iter(std::string_view name);

// Iterator state must live on the stack at an 8 byte aligned offset. The
// verifier recognizes it by the "bpf_iter_" struct name prefix.
bool is_bpf_iter_state(const SizedType &type);

} // namespace bpftrace
