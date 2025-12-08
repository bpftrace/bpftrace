#pragma once

#include <memory>
#include <optional>
#include <set>
#include <string>

#include "util/elf_parser.h"

namespace bpftrace::util {

// Interface for user-space symbol and function information.
//
// This abstraction allows components to query user-space symbols without
// performing direct file I/O, enabling mocking in tests.
class UserFunctionInfo {
public:
  virtual ~UserFunctionInfo() = default;

  // Get symbols from a file (for uprobe/uretprobe).
  virtual Result<std::unique_ptr<std::istream>> get_symbols_from_file(
      const std::string &path) = 0;

  // Get function symbols from a file (for uprobe/uretprobe).
  virtual Result<std::unique_ptr<std::istream>> get_func_symbols_from_file(
      std::optional<int> pid,
      const std::string &path) = 0;

  // Get USDT symbols from a target.
  virtual Result<std::unique_ptr<std::istream>> get_symbols_from_usdt(
      std::optional<int> pid,
      const std::string &target) = 0;

  // Find a specific USDT probe.
  virtual Result<usdt_probe_entry> find_usdt(
      std::optional<int> pid,
      const std::string &target,
      const std::string &provider,
      const std::string &name) = 0;

  // Get all USDT probes for a specific PID.
  virtual Result<usdt_probe_list> usdt_probes_for_pid(int pid) = 0;

  // Get all USDT probes for all running PIDs.
  virtual Result<usdt_probe_list> usdt_probes_for_all_pids() = 0;

  // Get all USDT probes for a specific path.
  virtual Result<usdt_probe_list> usdt_probes_for_path(
      const std::string &path) = 0;
};

// Concrete implementation that performs real file I/O.
class UserFunctionInfoImpl : public UserFunctionInfo {
public:
  UserFunctionInfoImpl() = default;
  ~UserFunctionInfoImpl() override = default;

  Result<std::unique_ptr<std::istream>> get_symbols_from_file(
      const std::string &path) override;

  Result<std::unique_ptr<std::istream>> get_func_symbols_from_file(
      std::optional<int> pid,
      const std::string &path) override;

  Result<std::unique_ptr<std::istream>> get_symbols_from_usdt(
      std::optional<int> pid,
      const std::string &target) override;

  Result<usdt_probe_entry> find_usdt(
      std::optional<int> pid,
      const std::string &target,
      const std::string &provider,
      const std::string &name) override;

  Result<usdt_probe_list> usdt_probes_for_pid(int pid) override;

  Result<usdt_probe_list> usdt_probes_for_all_pids() override;

  Result<usdt_probe_list> usdt_probes_for_path(
      const std::string &path) override;

private:
    Result<> read_probes_for_pid(int pid);
Result<> read_probes_for_path(const std::string& path);

    // Maps a pid to a set of paths for its probes.
    std::unordered_map<int, std::set<std::string>>
        pid_to_paths_;

// Maps all traced paths and all their providers to vector of tracepoints
// on each provider.
std::unordered_map<std::string,
                          std::unordered_map<std::string, usdt_probe_list>>
    path_to_probes_;
};

} // namespace bpftrace::util
