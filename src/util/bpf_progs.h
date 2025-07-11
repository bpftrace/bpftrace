#pragma once

#include <optional>
#include <string>
#include <unordered_set>

#include "util/fd.h"

namespace bpftrace::util {

// These include all BPF programs and subprograms
std::optional<FD> get_fd_for_bpf_prog(const std::string& bpf_prog_name,
                                      uint32_t prog_id);
std::unordered_set<std::string> get_bpf_program_symbols();

} // namespace bpftrace::util
