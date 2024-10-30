#pragma once

#include <map>
#include <string>

namespace bpftrace {

enum class Kfunc {
  bpf_map_sum_elem_count,
};

static const std::map<Kfunc, std::string> KFUNC_NAME_MAP = {
  { Kfunc::bpf_map_sum_elem_count, "bpf_map_sum_elem_count" },
};

inline const std::string &kfunc_name(enum Kfunc kfunc)
{
  return KFUNC_NAME_MAP.at(kfunc);
}

} // namespace bpftrace
