#include <algorithm>
#include <array>
#include <climits>
#include <filesystem>
#include <fstream>
#include <linux/limits.h>
#include <map>
#include <unordered_set>

#include "log.h"
#include "util/exceptions.h"
#include "util/system.h"

namespace bpftrace::util {

Result<std::string> get_pid_exe(const std::string &pid)
{
  std::error_code ec;
  std::filesystem::path proc_path{ "/proc" };
  proc_path /= pid;
  proc_path /= "exe";

  auto path = std::filesystem::read_symlink(proc_path, ec);
  if (ec) {
    return make_error<SystemError>("Unable to read '" + proc_path.string() +
                                       "'",
                                   ec.value());
  }
  return path.string();
}

Result<std::string> get_pid_exe(pid_t pid)
{
  return get_pid_exe(std::to_string(pid));
}

Result<std::string> get_proc_maps(const std::string &pid)
{
  std::error_code ec;
  std::filesystem::path proc_path{ "/proc" };
  proc_path /= pid;
  proc_path /= "maps";

  bool exists = std::filesystem::exists(proc_path, ec);
  if (ec) {
    return make_error<SystemError>("Unable to stat '" + proc_path.string() +
                                       "'",
                                   ec.value());
  }
  if (!exists) {
    return make_error<SystemError>("Process no longer exists", ENOENT);
  }
  return proc_path.string();
}

Result<std::string> get_proc_maps(pid_t pid)
{
  return get_proc_maps(std::to_string(pid));
}

Result<std::vector<int>> get_pids_for_program(const std::string &program)
{
  std::error_code ec;
  auto program_abs = std::filesystem::canonical(program, ec);
  if (ec) {
    // std::filesystem::canonical will fail if we are attaching to a uprobe that
    // lives in another filesystem namespace. For example,
    // uprobe:/proc/12345/root/my_program:function1
    // This shouldn't be a fatal condition as this function is only used to
    // attach to all running processes for a given binary, and the above uprobe
    // is targetting a specific process. So if this happens, just return no
    // pids. The probe will still attach directly to the targeted process.
    return make_error<SystemError>("Unable to canonicalize '" + program + "'",
                                   ec.value());
  }

  std::vector<int> pids;
  for (const auto &process : std::filesystem::directory_iterator("/proc")) {
    std::string filename = process.path().filename().string();
    if (!std::ranges::all_of(filename, ::isdigit))
      continue;
    std::error_code ec;
    std::filesystem::path pid_program = std::filesystem::read_symlink(
        process.path() / "exe", ec);
    if (!ec && program_abs == pid_program)
      pids.emplace_back(std::stoi(filename));
  }
  return pids;
}

Result<std::vector<int>> get_all_running_pids()
{
  std::vector<int> pids;
  for (const auto &process : std::filesystem::directory_iterator("/proc")) {
    std::string filename = process.path().filename().string();
    if (!std::ranges::all_of(filename, ::isdigit))
      continue;
    pids.emplace_back(std::stoi(filename));
  }
  return pids;
}

Result<std::string> exec_system(const char *cmd)
{
  std::array<char, 128> buffer;
  std::string result;
  std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
  if (!pipe) {
    return make_error<SystemError>("popen() failed");
  }
  while (!feof(pipe.get())) {
    if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
      result += buffer.data();
  }
  return result;
}

Result<std::vector<std::string>> get_mapped_paths_for_pid(pid_t pid)
{
  static std::map<pid_t, std::vector<std::string>> paths_cache;

  auto it = paths_cache.find(pid);
  if (it != paths_cache.end()) {
    return it->second;
  }

  std::vector<std::string> paths;

  // start with the exe.
  auto pid_exe = get_pid_exe(pid);
  if (pid_exe && pid_exe->find("(deleted)") == std::string::npos)
    paths.push_back(*pid_exe);

  // get all the mapped libraries.
  auto maps_path = get_proc_maps(pid);
  if (!maps_path) {
    return maps_path.takeError();
  }

  std::fstream fs(*maps_path, std::ios_base::in);
  if (!fs.is_open()) {
    return make_error<SystemError>("Unable to open procfs mapfile '" +
                                   *maps_path + "'");
  }

  std::unordered_set<std::string> seen_mappings;

  std::string line;
  // Example mapping:
  // 7fc8ee4fa000-7fc8ee4fb000 r--p 00000000 00:1f 27168296 /usr/libc.so.6
  while (std::getline(fs, line)) {
    char buf[PATH_MAX + 1];
    buf[0] = '\0';
    auto res = std::sscanf(line.c_str(), "%*s %*s %*x %*s %*u %[^\n]", buf);
    // skip [heap], [vdso], and non file paths etc...
    if (res == 1 && buf[0] == '/') {
      std::string name = buf;
      if (name.find("(deleted)") == std::string::npos &&
          !seen_mappings.contains(name)) {
        seen_mappings.emplace(name);
        paths.push_back(std::move(name));
      }
    }
  }

  paths_cache.emplace(pid, paths);
  return paths;
}

Result<std::vector<std::string>> get_mapped_paths_for_running_pids()
{
  std::unordered_set<std::string> unique_paths;
  auto pids = get_all_running_pids();
  if (!pids) {
    return pids.takeError();
  }
  for (auto pid : *pids) {
    auto mapped_paths = get_mapped_paths_for_pid(pid);
    if (!mapped_paths) {
      continue; // May have exited, etc.
    }
    for (auto &path : *mapped_paths) {
      unique_paths.insert(std::move(path));
    }
  }
  std::vector<std::string> paths;
  for (const auto &path : unique_paths) {
    paths.emplace_back(std::move(path));
  }
  return paths;
}

} // namespace bpftrace::util
