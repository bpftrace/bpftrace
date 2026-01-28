#pragma once

#include <optional>
#include <set>
#include <string>
#include <map>

#include "util/elf_parser.h"
#include "util/result.h"

namespace bpftrace::util {

using FunctionSet = std::set<std::string>;
using USDTSet = std::set<usdt_probe_entry>;
using BinaryUSDTMap = std::map<std::string, USDTSet>;
using BinaryFuncMap = std::map<std::string, FunctionSet>;

// Interface for user-space symbol and function information.
//
// This abstraction allows components to query user-space symbols without
// performing direct file I/O, enabling mocking in tests.
class UserFunctionInfo {
public:
  virtual ~UserFunctionInfo() = default;

  // Get function symbols for a specific PID.
  //
  // This looks up all associated binaries and libraries for the PID,
  // and effectively aggreagtes the result of `func_symbols_for_path`
  // on each of those individual files.
  virtual Result<BinaryFuncMap> func_symbols_for_pid(int pid) const = 0;

  // Get function symbols from a file.
  //
  // This parses the underlying ELF file, and extracts the set of function
  // symbols that are defined that can be traced.
  virtual Result<FunctionSet> func_symbols_for_path(
      const std::string &path) const = 0;

  // Get all USDT probes for a specific PID.
  //
  // Like `func_symbols_for_pid`, this effectively aggreagtes all USDTs defined
  // in any executable or library associated with the provided PID.
  virtual Result<BinaryUSDTMap> usdt_probes_for_pid(int pid) const = 0;

  // Get all USDT probes for all running PIDs.
  //
  // This aggregates all USDTs available for all running processes; be careful,
  // this can be a very expensive operation.
  virtual Result<BinaryUSDTMap> usdt_probes_for_all_pids() const = 0;

  // Get all USDT probes for a specific path.
  //
  // Like `func_symbols_for_path`, this is expected to parse the individual
  // USDT providers and probes for a specific file, denoted by `path`.
  virtual Result<USDTSet> usdt_probes_for_path(
      const std::string &path) const = 0;
};

// Concrete implementation that performs real file I/O.
//
// This opens files on the local system and parsing ELF for symbol
// and USDT information about the specific binaries.
class UserFunctionInfoImpl : public UserFunctionInfo {
public:
  UserFunctionInfoImpl() = default;
  ~UserFunctionInfoImpl() override = default;

 Result<BinaryFuncMap> func_symbols_for_pid(int pid) const override;
 Result<FunctionSet> func_symbols_for_path(
    const std::string &path) const override;
  Result<BinaryUSDTMap> usdt_probes_for_pid(int pid) const override;
  Result<BinaryUSDTMap> usdt_probes_for_all_pids() const override;
  Result<USDTSet> usdt_probes_for_path(
      const std::string &path) const override;

private:
  Result<> read_probes_for_pid(int pid) const;
  Result<> read_probes_for_path(const std::string& path) const;

  // Maps a pid to a set of paths for its probes.
  mutable std::unordered_map<int, std::set<std::string>> pid_to_paths_;

  // Maps all paths to the discovered symbols.
  mutable BinaryFuncMap path_to_symbols_;

  // Maps all paths and all their providers to scanned USDTs.
  mutable BinaryUSDTMap path_to_usdt_;
};

} // namespace bpftrace::util
