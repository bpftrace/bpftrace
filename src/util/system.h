#pragma once

#include <string>
#include <vector>

namespace bpftrace::util {

std::string get_pid_exe(pid_t pid);
std::string get_pid_exe(const std::string &pid);
std::string get_proc_maps(const std::string &pid);
std::string get_proc_maps(pid_t pid);

std::string exec_system(const char *cmd);

std::vector<std::string> get_mapped_paths_for_pid(pid_t pid);
std::vector<std::string> get_mapped_paths_for_running_pids();

std::vector<int> get_pids_for_program(const std::string &program);
std::vector<int> get_all_running_pids();

} // namespace bpftrace::util
