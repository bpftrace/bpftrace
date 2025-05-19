#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

struct FilterInputs {
  std::optional<pid_t> pid;
  std::optional<uint64_t> cgroup_id;
};

Pass CreateFilterPass(const FilterInputs &inputs);

} // namespace bpftrace::ast
