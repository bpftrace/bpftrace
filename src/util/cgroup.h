#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace bpftrace::util {

std::string get_cgroup_path_in_hierarchy(uint64_t cgroupid,
                                         std::string base_path);

std::array<std::vector<std::string>, 2> get_cgroup_hierarchy_roots();

std::vector<std::pair<std::string, std::string>> get_cgroup_paths(
    uint64_t cgroupid,
    std::string filter);

uint64_t resolve_cgroupid(const std::string &path);

} // namespace bpftrace::util
