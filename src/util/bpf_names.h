#pragma once

#include <optional>
#include <string>

namespace bpftrace::util {

std::string sanitise_bpf_program_name(const std::string &name);

// Generate object file function name for a given probe
inline std::string get_function_name_for_probe(
    const std::string &probe_name,
    int index)
{
  return sanitise_bpf_program_name(probe_name) + "_" + std::to_string(index);
}

inline std::string get_section_name(const std::string &function_name)
{
  return "s_" + function_name;
}

inline std::string get_watchpoint_setup_probe_name(
    const std::string &probe_name)
{
  return probe_name + "_wp_setup";
}

inline std::string get_function_name_for_watchpoint_setup(
    const std::string &probe_name,
    int index)
{
  return get_function_name_for_probe(
      get_watchpoint_setup_probe_name(probe_name), index);
}

} // namespace bpftrace::util
