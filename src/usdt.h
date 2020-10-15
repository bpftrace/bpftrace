#pragma once

#include <optional>
#include <string>
#include <vector>

struct usdt_probe_entry
{
  std::string path;
  std::string provider;
  std::string name;
  uint64_t semaphore_offset;
  int num_locations;
};

typedef std::vector<usdt_probe_entry> usdt_probe_list;

// Note this class is fully static because bcc_usdt_foreach takes a function
// pointer callback without a context variable. So we must keep global state.
class USDTHelper
{
public:
  static std::optional<usdt_probe_entry> find(int pid,
                                              const std::string &target,
                                              const std::string &provider,
                                              const std::string &name);
  static usdt_probe_list probes_for_pid(int pid);
  static usdt_probe_list probes_for_path(const std::string &path);

private:
  static void read_probes_for_pid(int pid);
  static void read_probes_for_path(const std::string &path);
};
