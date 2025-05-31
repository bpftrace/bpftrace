#pragma once

#include <map>
#include <string>

namespace bpftrace {

enum class Kfunc {
  bpf_map_sum_elem_count,
  bpf_session_is_return,
  bpf_task_from_pid,
  bpf_task_release,
};

static const std::map<Kfunc, std::string> KFUNC_NAME_MAP = {
  { Kfunc::bpf_map_sum_elem_count, "bpf_map_sum_elem_count" },
  { Kfunc::bpf_session_is_return, "bpf_session_is_return" },
  { Kfunc::bpf_task_from_pid, "bpf_task_from_pid" },
  { Kfunc::bpf_task_release, "bpf_task_release" },
};

inline const std::string &kfunc_name(enum Kfunc kfunc)
{
  return KFUNC_NAME_MAP.at(kfunc);
}

} // namespace bpftrace
