#pragma once

#include "util/elf_parser.h"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bpftrace {

class USDTHelper {
public:
  virtual ~USDTHelper() = default;

  virtual std::optional<util::usdt_probe_entry> find(
      std::optional<int> pid,
      const std::string &target,
      const std::string &provider,
      const std::string &name,
      bool has_uprobe_multi);
  static util::usdt_probe_list probes_for_pid(int pid,
                                              bool has_uprobe_multi,
                                              bool print_error = true);
  static util::usdt_probe_list probes_for_all_pids(bool has_uprobe_multi);
  static util::usdt_probe_list probes_for_path(const std::string &path,
                                               bool has_uprobe_multi);

private:
  static void read_probes_for_pid(int pid,
                                  bool has_uprobe_multi,
                                  bool print_error = true);
  static void read_probes_for_path(const std::string &path,
                                   bool has_uprobe_multi);
};

} // namespace bpftrace
