#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "util/elf_parser.h"

namespace bpftrace {

// Note this class is fully static because bcc_usdt_foreach takes a function
// pointer callback without a context variable. So we must keep global state.
class USDTHelper {
public:
  virtual ~USDTHelper() = default;

  virtual std::optional<util::usdt_probe_entry> find(std::optional<int> pid,
                                               const std::string &target,
                                               const std::string &provider,
                                               const std::string &name);
  static util::usdt_probe_list probes_for_pid(int pid, bool print_error = true);
  static util::usdt_probe_list probes_for_all_pids();
  static util::usdt_probe_list probes_for_path(const std::string &path);

private:
  static void read_probes_for_pid(int pid, bool print_error = true);
  static void read_probes_for_path(const std::string &path);
};

} // namespace bpftrace
