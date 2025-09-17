#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bpftrace {

struct usdt_probe_entry {
  std::string path;
  std::string provider;
  std::string name;
  uint64_t semaphore_offset;
  int num_locations;
};

using usdt_probe_list = std::vector<usdt_probe_entry>;

// Note this class is fully static because bcc_usdt_foreach takes a function
// pointer callback without a context variable. So we must keep global state.
class USDTHelper {
public:
  virtual ~USDTHelper() = default;

  virtual std::optional<usdt_probe_entry> find(std::optional<int> pid,
                                               const std::string &target,
                                               const std::string &provider,
                                               const std::string &name,
                                              bool has_uprobe_multi);
  static usdt_probe_list probes_for_pid(int pid, bool has_uprobe_multi, bool print_error = true);
  static usdt_probe_list probes_for_all_pids(bool has_uprobe_multi);
  static usdt_probe_list probes_for_path(const std::string &path, bool has_uprobe_multi);

private:
  static void read_probes_for_pid(int pid, bool has_uprobe_multi, bool print_error = true);
  static void read_probes_for_path(const std::string &path, bool has_uprobe_multi);
};

} // namespace bpftrace
