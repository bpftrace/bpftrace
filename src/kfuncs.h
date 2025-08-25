#pragma once

#include <map>
#include <string>

namespace bpftrace {

enum class Kfunc {
  bpf_map_sum_elem_count,
  bpf_session_is_return,
  bpf_strcmp,
  bpf_strlen,
  bpf_strnlen,
  bpf_strspn,
  bpf_strcspn,
  bpf_strnstr,
  bpf_strstr,
};

static const std::map<Kfunc, std::string> KFUNC_NAME_MAP = {
  { Kfunc::bpf_map_sum_elem_count, "bpf_map_sum_elem_count" },
  { Kfunc::bpf_session_is_return, "bpf_session_is_return" },
  { Kfunc::bpf_strcmp, "bpf_strcmp" },
  { Kfunc::bpf_strlen, "bpf_strlen" },
  { Kfunc::bpf_strnlen, "bpf_strnlen" },
  { Kfunc::bpf_strspn, "bpf_strspn" },
  { Kfunc::bpf_strcspn, "bpf_strcspn" },
  { Kfunc::bpf_strnstr, "bpf_strnstr" },
  { Kfunc::bpf_strstr, "bpf_strstr" },
};

inline const std::string &kfunc_name(enum Kfunc kfunc)
{
  return KFUNC_NAME_MAP.at(kfunc);
}

} // namespace bpftrace
