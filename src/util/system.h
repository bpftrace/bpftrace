#pragma once

#include <string>
#include <vector>

#include "util/result.h"

namespace bpftrace::util {

Result<std::string> get_pid_exe(pid_t pid);
Result<std::string> get_pid_exe(const std::string &pid);
Result<std::string> get_proc_maps(const std::string &pid);
Result<std::string> get_proc_maps(pid_t pid);

Result<std::string> exec_system(const char *cmd);

Result<std::vector<std::string>> get_mapped_paths_for_pid(pid_t pid);
Result<std::vector<std::string>> get_mapped_paths_for_running_pids();

Result<std::vector<int>> get_pids_for_program(const std::string &program);
Result<std::vector<int>> get_all_running_pids();

} // namespace bpftrace::util
