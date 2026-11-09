#include "util/bpf_funcs.h"

#define __BPF_NAME_FN(x) #x
const char* bpf_func_name[] = { __BPF_FUNC_MAPPER(__BPF_NAME_FN) };
#undef __BPF_NAME_FN

std::ostream& operator<<(std::ostream& out, const bpf_func_id& id)
{
  out << bpf_func_name[id];
  return out;
}

std::optional<bpf_func_id> helper_id_from_name(std::string_view name)
{
  if (!name.starts_with("bpf_")) {
    return std::nullopt;
  }
  name.remove_prefix(4);
  // Index 0 is BPF_FUNC_unspec, which is not a callable helper.
  for (int i = 1; i < __BPF_FUNC_MAX_ID; i++) {
    if (name == bpf_func_name[i]) {
      return static_cast<bpf_func_id>(i);
    }
  }
  return std::nullopt;
}
