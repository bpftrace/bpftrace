#include <algorithm>
#include <csignal>
#include <unordered_map>
#include <unordered_set>

#include "log.h"
#include "usdt.h"
#include "util/elf_parser.h"
#include "util/system.h"

namespace bpftrace {

static std::unordered_set<std::string> path_cache;
static std::unordered_set<int> pid_cache;

// Maps all traced paths and all their providers to vector of tracepoints
// on each provider
static std::unordered_map<
    std::string,
    std::unordered_map<std::string, util::usdt_probe_list>>
    usdt_provider_cache;

// Maps a pid to a set of paths for its probes
static std::unordered_map<int, std::unordered_set<std::string>>
    usdt_pid_to_paths_cache;

// Used as a temporary buffer, during read_probes_for_pid to maintain
// current tracepoint paths for the current pid
static std::unordered_set<std::string> current_pid_paths;

static bool has_uprobe_multi_ = false;

static void usdt_probe_each(struct util::usdt_probe_entry &usdt_probe)
{
  usdt_provider_cache[usdt_probe.path][usdt_probe.provider].emplace_back(
      usdt_probe.path,
      usdt_probe.provider,
      usdt_probe.name,
      usdt_probe.sema_addr,
      usdt_probe.sema_offset);
  current_pid_paths.emplace(usdt_probe.path);
}

// Move the current pid paths onto the pid_to_paths_cache, and clear
// current_pid_paths.
static void cache_current_pid_paths(int pid)
{
  usdt_pid_to_paths_cache[pid].merge(current_pid_paths);
  current_pid_paths.clear();
}

std::optional<util::usdt_probe_entry> USDTHelper::find(
    std::optional<int> pid,
    const std::string &target,
    const std::string &provider,
    const std::string &name,
    bool has_uprobe_multi)
{
  util::usdt_probe_list probes;
  if (pid.has_value()) {
    read_probes_for_pid(*pid, has_uprobe_multi);
    for (auto const &path : usdt_pid_to_paths_cache[*pid]) {
      probes.insert(probes.end(),
                    usdt_provider_cache[path][provider].begin(),
                    usdt_provider_cache[path][provider].end());
    }
  } else {
    read_probes_for_path(target, has_uprobe_multi);
    probes = usdt_provider_cache[target][provider];
  }

  auto it = std::ranges::find_if(probes,

                                 [&name](const util::usdt_probe_entry &e) {
                                   return e.name == name;
                                 });
  if (it != probes.end()) {
    return *it;
  } else {
    return std::nullopt;
  }
}

util::usdt_probe_list USDTHelper::probes_for_pid(int pid,
                                                 bool has_uprobe_multi,
                                                 bool print_error)
{
  read_probes_for_pid(pid, has_uprobe_multi, print_error);

  util::usdt_probe_list probes;
  for (auto const &path : usdt_pid_to_paths_cache[pid]) {
    for (auto const &usdt_probes : usdt_provider_cache[path]) {
      probes.insert(probes.end(),
                    usdt_probes.second.begin(),
                    usdt_probes.second.end());
    }
  }
  return probes;
}

util::usdt_probe_list USDTHelper::probes_for_all_pids(bool has_uprobe_multi)
{
  util::usdt_probe_list probes;
  auto pids = util::get_all_running_pids();
  if (!pids) {
    LOG(ERROR) << "Unable to get pids: " << pids.takeError();
    return probes;
  }
  for (int pid : *pids) {
    for (auto &probe : probes_for_pid(pid, has_uprobe_multi, false)) {
      probes.push_back(std::move(probe));
    }
  }
  return probes;
}

util::usdt_probe_list USDTHelper::probes_for_path(const std::string &path,
                                                  bool has_uprobe_multi)
{
  read_probes_for_path(path, has_uprobe_multi);

  util::usdt_probe_list probes;
  for (auto const &usdt_probes : usdt_provider_cache[path]) {
    probes.insert(probes.end(),
                  usdt_probes.second.begin(),
                  usdt_probes.second.end());
  }
  return probes;
}

void USDTHelper::read_probes_for_pid(int pid,
                                     bool has_uprobe_multi,
                                     bool print_error)
{
  has_uprobe_multi_ = has_uprobe_multi;
  if (pid_cache.contains(pid))
    return;

  auto result = util::get_mapped_paths_for_pid(pid);
  if (!result && print_error) {
    LOG(ERROR) << result.takeError();
    return;
  }
  for (auto const &path : *result) {
    if (current_pid_paths.contains(path)) {
      continue;
    }
    read_probes_for_path(path, has_uprobe_multi);
    current_pid_paths.emplace(path);
  }
  cache_current_pid_paths(pid);

  pid_cache.emplace(pid);
}

void USDTHelper::read_probes_for_path(const std::string &path,
                                      bool has_uprobe_multi)
{
  has_uprobe_multi_ = has_uprobe_multi;
  if (path_cache.contains(path))
    return;

  auto enumerator = util::make_usdt_probe_enumerator(path);
  if (!enumerator) {
    LOG(ERROR) << enumerator.takeError();
    return;
  }
  auto probes_res = enumerator->enumerate_probes();
  if (!probes_res) {
    LOG(ERROR) << probes_res.takeError();
    return;
  }
  auto probes = *probes_res;
  std::ranges::for_each(probes, usdt_probe_each);
  path_cache.emplace(path);
}

} // namespace bpftrace
