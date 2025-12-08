#include "user.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

#include "log.h"
#include "util/elf_parser.h"
#include "util/paths.h"
#include "util/system.h"

#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <elf.h>

namespace bpftrace::util {

static int add_symbol(const char* symname,
                      uint64_t /*start*/,
                      uint64_t /*size*/,
                      void* payload)
{
  auto* syms = static_cast<std::set<std::string>*>(payload);
  syms->insert(std::string(symname));
  return 0;
}

Result<> UserFunctionInfoImpl::read_probes_for_pid(int pid) const
{
  if (pid_to_paths_.contains(pid))
    return OK();

  auto result = get_mapped_paths_for_pid(pid);
  if (!result) {
    return result.takeError();
  }
  for (auto const& path : *result) {
    auto ok = read_probes_for_path(path);
    if (!ok) {
      // Not all paths will have probes, so we just disregard this
      // path and presume that there were no probes present. This is
      // unlike the case where we have explicitly provided a path,
      // where we will propagte the error if there are no probes.
      //
      // Consider a binary that has probes in the main executable,
      // but is linked against a probeless libc (common case).
      continue;
    }
    pid_to_paths_[pid].emplace(path);
  }

  return OK();
}

Result<> UserFunctionInfoImpl::read_probes_for_path(
    const std::string& path) const
{
  if (path_to_probes_.contains(path)) {
    return OK();
  }

  auto enumerator = make_usdt_probe_enumerator(path);
  if (!enumerator) {
    return enumerator.takeError();
  }
  auto probes_res = enumerator->enumerate_probes();
  if (!probes_res) {
    return probes_res.takeError();
  }
  path_to_probes_[path]; // Ensure we have an empty entry.
  auto probes = *probes_res;
  std::ranges::for_each(probes, [&](struct usdt_probe_entry& usdt_probe) {
    path_to_probes_[usdt_probe.path][usdt_probe.provider].emplace_back(
        usdt_probe.path,
        usdt_probe.provider,
        usdt_probe.name,
        usdt_probe.sema_addr,
        usdt_probe.sema_offset);
  });

  return OK();
}

Result<std::unique_ptr<std::istream>> UserFunctionInfoImpl::
    get_symbols_from_file(const std::string& path) const
{
  auto file = std::make_unique<std::ifstream>(path);
  if (file->fail()) {
    LOG(WARNING) << "Could not read symbols from " << path << ": "
                 << strerror(errno);
    return nullptr;
  }

  return file;
}

Result<std::unique_ptr<std::istream>> UserFunctionInfoImpl::
    get_func_symbols_from_file(std::optional<int> pid,
                               const std::string& path) const
{
  if (path.empty())
    return std::make_unique<std::istringstream>("");

  auto get_paths = [&]() -> Result<std::vector<std::string>> {
    if (path == "*") {
      if (pid.has_value()) {
        return util::get_mapped_paths_for_pid(*pid);
      } else {
        return util::get_mapped_paths_for_running_pids();
      }
    } else if (path.find('*') != std::string::npos) {
      return util::resolve_binary_path(path, pid);
    } else {
      return std::vector<std::string>({ path });
    }
  };
  auto real_paths = get_paths();
  if (!real_paths) {
    return real_paths.takeError();
  }

  struct bcc_symbol_option symbol_option;
  memset(&symbol_option, 0, sizeof(symbol_option));
  symbol_option.use_debug_file = 1;
  symbol_option.check_debug_file_crc = 1;
  symbol_option.use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC);

  std::string result;
  for (auto& real_path : *real_paths) {
    std::set<std::string> syms;
    // Workaround: bcc_elf_foreach_sym() can return the same symbol twice if
    // it's also found in debug info (#1138), so a std::set is used here
    // (and in the add_symbol callback) to ensure that each symbol will be
    // unique in the returned string.
    int err = bcc_elf_foreach_sym(
        real_path.c_str(), add_symbol, &symbol_option, &syms);
    if (err) {
      LOG(WARNING) << "Could not list function symbols: " + real_path;
    }
    for (const auto& sym : syms)
      result += real_path + ":" + sym + "\n";
  }
  return std::make_unique<std::istringstream>(result);
}

Result<std::unique_ptr<std::istream>> UserFunctionInfoImpl::
    get_symbols_from_usdt(std::optional<int> pid,
                          const std::string& target) const
{
  auto usdt_probes = [&]() -> Result<usdt_probe_list> {
    if (pid.has_value()) {
      return usdt_probes_for_pid(*pid);
    } else if (target == "*" || target.empty()) {
      return usdt_probes_for_all_pids();
    } else {
      std::vector<std::string> real_paths;
      if (target.find('*') != std::string::npos)
        real_paths = util::resolve_binary_path(target);
      else
        real_paths.push_back(target);

      usdt_probe_list usdt_probes;
      for (auto& real_path : real_paths) {
        auto target_usdt_probes = usdt_probes_for_path(real_path);
        if (!target_usdt_probes) {
          return target_usdt_probes.takeError();
        }
        usdt_probes.insert(usdt_probes.end(),
                           target_usdt_probes->begin(),
                           target_usdt_probes->end());
      }
      return usdt_probes;
    }
  }();
  if (!usdt_probes) {
    return usdt_probes.takeError();
  }

  std::string probes;
  for (auto const& usdt_probe : *usdt_probes) {
    std::string path = usdt_probe.path;
    std::string provider = usdt_probe.provider;
    std::string fname = usdt_probe.name;
    probes += path + ":" + provider + ":" + fname + "\n";
  }

  return std::make_unique<std::istringstream>(probes);
}

Result<usdt_probe_entry> UserFunctionInfoImpl::find_usdt(
    std::optional<int> pid,
    const std::string& target,
    const std::string& provider,
    const std::string& name) const
{
  usdt_probe_list probes;
  if (pid.has_value()) {
    auto ok = read_probes_for_pid(*pid);
    if (!ok) {
      return ok.takeError();
    }
    for (const auto& path : pid_to_paths_[*pid]) {
      probes.insert(probes.end(),
                    path_to_probes_[path][provider].begin(),
                    path_to_probes_[path][provider].end());
    }
  } else {
    auto ok = read_probes_for_path(target);
    if (!ok) {
      return ok.takeError();
    }
    probes = path_to_probes_[target][provider];
  }

  auto it = std::ranges::find_if(probes, [&name](const usdt_probe_entry& e) {
    return e.name == name;
  });
  if (it != probes.end()) {
    return *it;
  } else {
    // The named probe did not exist; we return an error here because
    // this function has been given a full spec and it does not exist.
    return make_error<SystemError>("USDT probe not found", ENOENT);
  }
}

Result<usdt_probe_list> UserFunctionInfoImpl::usdt_probes_for_pid(int pid) const
{
  auto ok = read_probes_for_pid(pid);
  if (!ok) {
    return ok.takeError();
  }

  usdt_probe_list probes;
  for (auto const& path : pid_to_paths_[pid]) {
    for (auto const& usdt_probes : path_to_probes_[path]) {
      probes.insert(probes.end(),
                    usdt_probes.second.begin(),
                    usdt_probes.second.end());
    }
  }
  return probes;
}

Result<usdt_probe_list> UserFunctionInfoImpl::usdt_probes_for_all_pids() const
{
  usdt_probe_list probes;
  auto pids = get_all_running_pids();
  if (!pids) {
    return pids.takeError();
  }
  for (int pid : *pids) {
    auto pid_probes = usdt_probes_for_pid(pid);
    if (!pid_probes) {
      continue; // Best effort, don't surface this error.
    }
    for (auto& probe : *pid_probes) {
      probes.push_back(std::move(probe));
    }
  }
  return probes;
}

Result<usdt_probe_list> UserFunctionInfoImpl::usdt_probes_for_path(
    const std::string& path) const
{
  auto ok = read_probes_for_path(path);
  if (!ok) {
    return ok.takeError();
  }

  usdt_probe_list probes;
  for (auto const& usdt_probes : path_to_probes_[path]) {
    probes.insert(probes.end(),
                  usdt_probes.second.begin(),
                  usdt_probes.second.end());
  }
  return probes;
}

} // namespace bpftrace::util
