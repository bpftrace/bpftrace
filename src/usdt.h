#pragma once

#include <string>
#include <vector>

struct usdt_probe_entry
{
  std::string path;
  std::string provider;
  std::string name;
  int num_locations;
};

typedef std::vector<usdt_probe_entry> usdt_probe_list;

class USDTHelper
{
public:
  static usdt_probe_entry find(int pid,
                               const std::string &target,
                               const std::string &provider,
                               const std::string &name);
  static usdt_probe_list probes_for_provider(const std::string &provider);
  static usdt_probe_list probes_for_pid(int pid);
  static usdt_probe_list probes_for_path(const std::string &path);
  static void read_probes_for_pid(int pid);
  static void read_probes_for_path(const std::string &path);
};
