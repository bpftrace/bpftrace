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
      const std::string &path) const = 0;

  // Get function symbols from a file (for uprobe/uretprobe).
  virtual Result<std::unique_ptr<std::istream>> get_func_symbols_from_file(
      std::optional<int> pid,
      const std::string &path) const = 0;

  // Get USDT symbols from a target.
  virtual Result<std::unique_ptr<std::istream>> get_symbols_from_usdt(
      std::optional<int> pid,
      const std::string &target) const = 0;

  // Find a specific USDT probe.
  virtual Result<usdt_probe_entry> find_usdt(
      std::optional<int> pid,
      const std::string &target,
      const std::string &provider,
      const std::string &name) const = 0;

  // Get all USDT probes for a specific PID.
  virtual Result<usdt_probe_list> usdt_probes_for_pid(int pid) const = 0;

  // Get all USDT probes for all running PIDs.
  virtual Result<usdt_probe_list> usdt_probes_for_all_pids() const = 0;

  // Get all USDT probes for a specific path.
  virtual Result<usdt_probe_list> usdt_probes_for_path(
      const std::string &path) const = 0;
};

// Concrete implementation that performs real file I/O.
class UserFunctionInfoImpl : public UserFunctionInfo {
public:
  UserFunctionInfoImpl() = default;
  ~UserFunctionInfoImpl() override = default;

  Result<std::unique_ptr<std::istream>> get_symbols_from_file(
      const std::string &path) const override;

  Result<std::unique_ptr<std::istream>> get_func_symbols_from_file(
      std::optional<int> pid,
      const std::string &path) const override;

  Result<std::unique_ptr<std::istream>> get_symbols_from_usdt(
      std::optional<int> pid,
      const std::string &target) const override;

  Result<usdt_probe_entry> find_usdt(
      std::optional<int> pid,
      const std::string &target,
      const std::string &provider,
      const std::string &name) const override;

  Result<usdt_probe_list> usdt_probes_for_pid(int pid) const override;

  Result<usdt_probe_list> usdt_probes_for_all_pids() const override;

  Result<usdt_probe_list> usdt_probes_for_path(
      const std::string &path) const override;

private:
  Result<> read_probes_for_pid(int pid) const;
  Result<> read_probes_for_path(const std::string& path) const;

  // Maps a pid to a set of paths for its probes.
  mutable std::unordered_map<int, std::set<std::string>> pid_to_paths_;

  // Maps all traced paths and all their providers to vector of tracepoints
  // on each provider.
  mutable std::unordered_map<std::string,
                             std::unordered_map<std::string,
                                                usdt_probe_list>>
    path_to_probes_;
};

} // namespace bpftrace::util
