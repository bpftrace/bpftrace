#pragma once

#include <string>
#include <vector>

#include "util/result.h"

namespace bpftrace::util {

class GetPidError : public ErrorInfo<GetPidError> {
public:
  GetPidError(int err) : err_(err) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  int err_;
};

Result<std::string> get_pid_exe(pid_t pid);
Result<std::string> get_pid_exe(const std::string &pid);
std::string get_proc_maps(const std::string &pid);
std::string get_proc_maps(pid_t pid);

std::string exec_system(const char *cmd);

std::vector<std::string> get_mapped_paths_for_pid(pid_t pid);
std::vector<std::string> get_mapped_paths_for_running_pids();

std::vector<int> get_pids_for_program(const std::string &program);
std::vector<int> get_all_running_pids();

} // namespace bpftrace::util
