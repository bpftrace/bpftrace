#pragma once

#include <format>
#include <string>

namespace bpftrace::util {

std::string sanitise_bpf_program_name(const std::string &name);

// Note that we generate a function name that is completely independent of the
// probe name, and encodes only the associated (unique) attach point index, as
// well as a possible inline index (which would have the same attach point).
inline std::string get_function_name_for_probe(size_t attach_index,
                                               size_t inline_index)
{
  return std::format("p{}_{}", attach_index, inline_index);
}

inline std::string get_watchpoint_setup_probe_name(size_t attach_index)
{
  return std::format("wp_setup_{}", attach_index);
}

inline std::string get_function_name_for_watchpoint_setup(size_t attach_index)
{
  return get_function_name_for_probe(attach_index, 0);
}

} // namespace bpftrace::util
