#pragma once

#include <optional>
#include <string>
#include <vector>

namespace bpftrace::util {

// This includes all BPF programs and subprograms
// the pair is (prog id, symbol)
std::vector<std::pair<__u32, std::string>> get_bpf_progs();

} // namespace bpftrace::util
