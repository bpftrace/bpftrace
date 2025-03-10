#pragma once

#include <optional>
#include <string>

namespace bpftrace::util {

std::string sanitise_bpf_program_name(const std::string &name);

// Generate object file function name for a given probe
inline std::string get_function_name_for_probe(
    const std::string &probe_name,
    int index,
    std::optional<int> usdt_location_index = std::nullopt)
{
  auto ret = sanitise_bpf_program_name(probe_name);

  if (usdt_location_index)
    ret += "_loc" + std::to_string(*usdt_location_index);

  ret += "_" + std::to_string(index);

  return ret;
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
