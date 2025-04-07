#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <gelf.h>
#include <glob.h>
#include <iostream>
#include <regex>
#include <unistd.h>

#include "log.h"
#include "scopeguard.h"
#include "util/exceptions.h"
#include "util/format.h"
#include "util/paths.h"

namespace bpftrace::util {

// Determines if the target process is in a different mount namespace from
// bpftrace.
//
// If a process is in a different mount namespace (eg, container) it is very
// likely that any references to local paths will not be valid, and that paths
// need to be made relative to the PID.
//
// If an invalid PID is specified or doesn't exist, it returns false.
// True is only returned if the namespace of the target process could be read
// and it doesn't match that of bpftrace. If there was an error reading either
// mount namespace, it will throw an exception
static bool pid_in_different_mountns(int pid)
{
  if (pid <= 0)
    return false;

  std::error_code ec;
  std::filesystem::path self_path{ "/proc/self/ns/mnt" };
  std::filesystem::path target_path{ "/proc" };
  target_path /= std::to_string(pid);
  target_path /= "ns/mnt";

  if (!std::filesystem::exists(self_path, ec)) {
    throw MountNSException(
        "Failed to compare mount ns with PID " + std::to_string(pid) +
        ". The error was open (/proc/self/ns/mnt): " + ec.message());
  }

  if (!std::filesystem::exists(target_path, ec)) {
    throw MountNSException(
        "Failed to compare mount ns with PID " + std::to_string(pid) +
        ". The error was open (/proc/<pid>/ns/mnt): " + ec.message());
  }

  bool result = !std::filesystem::equivalent(self_path, target_path, ec);

  if (ec) {
    throw MountNSException("Failed to compare mount ns with PID " +
                           std::to_string(pid) +
                           ". The error was (fstat): " + ec.message());
  }

  return result;
}

static bool has_exec_permission(const std::string &path)
{
  using std::filesystem::perms;

  auto perms = std::filesystem::status(path).permissions();
  return (perms & perms::owner_exec) != perms::none;
}

// Check whether 'path' refers to a ELF file. Errors are swallowed silently and
// result in return of 'nullopt'. On success, the ELF type (e.g., ET_DYN) is
// returned.
static std::optional<int> is_elf(const std::string &path)
{
  int fd;
  Elf *elf;
  GElf_Ehdr ehdr;

  if (elf_version(EV_CURRENT) == EV_NONE) {
    return std::nullopt;
  }

  fd = open(path.c_str(), O_RDONLY, 0);
  if (fd < 0) {
    return std::nullopt;
  }
  SCOPE_EXIT
  {
    ::close(fd);
  };

  elf = elf_begin(fd, ELF_C_READ, nullptr);
  if (elf == nullptr) {
    return std::nullopt;
  }
  SCOPE_EXIT
  {
    ::elf_end(elf);
  };

  if (elf_kind(elf) != ELF_K_ELF) {
    return std::nullopt;
  }

  if (!gelf_getehdr(elf, &ehdr)) {
    return std::nullopt;
  }

  return ehdr.e_type;
}

static std::vector<std::string> expand_wildcard_path(const std::string &path)
{
  glob_t glob_result;
  memset(&glob_result, 0, sizeof(glob_result));

  if (glob(path.c_str(), GLOB_NOCHECK, nullptr, &glob_result)) {
    globfree(&glob_result);
    throw FatalUserException("glob() failed");
  }

  std::vector<std::string> matching_paths;
  for (size_t i = 0; i < glob_result.gl_pathc; ++i) {
    matching_paths.emplace_back(glob_result.gl_pathv[i]);
  }

  globfree(&glob_result);
  return matching_paths;
}

static std::vector<std::string> expand_wildcard_paths(
    const std::vector<std::string> &paths)
{
  std::vector<std::string> expanded_paths;
  for (const auto &p : paths) {
    auto ep = expand_wildcard_path(p);
    expanded_paths.insert(expanded_paths.end(), ep.begin(), ep.end());
  }
  return expanded_paths;
}

// Private interface to resolve_binary_path, used for the exposed variants
// above, allowing for a PID whose mount namespace should be optionally
// considered.
static std::vector<std::string> resolve_binary_path(const std::string &cmd,
                                                    const char *env_paths,
                                                    std::optional<int> pid)
{
  std::vector<std::string> candidate_paths = { cmd };

  if (env_paths != nullptr && cmd.find("/") == std::string::npos)
    for (const auto &path : split_string(env_paths, ':'))
      candidate_paths.push_back(path + "/" + cmd);

  if (cmd.find("*") != std::string::npos)
    candidate_paths = expand_wildcard_paths(candidate_paths);

  std::vector<std::string> valid_executable_paths;
  for (const auto &path : candidate_paths) {
    std::string rel_path;
    if (pid.has_value() && pid_in_different_mountns(*pid))
      rel_path = path_for_pid_mountns(*pid, path);
    else
      rel_path = path;

    // Both executables and shared objects are game.
    if (auto e_type = is_elf(rel_path)) {
      if ((e_type == ET_EXEC && has_exec_permission(rel_path)) ||
          e_type == ET_DYN) {
        valid_executable_paths.push_back(rel_path);
      }
    }
  }

  return valid_executable_paths;
}

// If a pid is specified, the binary path is taken relative to its own PATH if
// it is in a different mount namespace. Otherwise, the path is resolved
// relative to the local PATH env var for bpftrace's own mount namespace if it
// is set
std::vector<std::string> resolve_binary_path(const std::string &cmd,
                                             std::optional<int> pid)
{
  std::string env_paths;
  std::ostringstream pid_environ_path;

  if (pid.has_value() && pid_in_different_mountns(*pid)) {
    pid_environ_path << "/proc/" << *pid << "/environ";
    std::ifstream environ(pid_environ_path.str());

    if (environ) {
      std::string env_var;
      std::string pathstr = ("PATH=");
      while (std::getline(environ, env_var, '\0')) {
        if (env_var.find(pathstr) != std::string::npos) {
          env_paths = env_var.substr(pathstr.length());
          break;
        }
      }
    }
    return resolve_binary_path(cmd, env_paths.c_str(), pid);
  } else {
    return resolve_binary_path(cmd, getenv("PATH"), pid);
  }
}

std::optional<std::filesystem::path> find_in_path(std::string_view name)
{
  std::error_code ec;

  const char *path_env = std::getenv("PATH");
  if (!path_env)
    return std::nullopt;

  auto paths = split_string(path_env, ':', true);
  for (const auto &path : paths) {
    auto fpath = std::filesystem::path(path) / name;
    if (std::filesystem::exists(fpath, ec))
      return fpath;
  }

  return std::nullopt;
}

std::optional<std::filesystem::path> find_near_self(std::string_view filename)
{
  std::error_code ec;
  auto exe = std::filesystem::read_symlink("/proc/self/exe", ec);
  if (ec) {
    LOG(WARNING) << "Failed to resolve /proc/self/exe: " << ec;
    return std::nullopt;
  }

  exe.replace_filename(filename);
  bool exists = std::filesystem::exists(exe, ec);
  if (!exists) {
    if (ec)
      LOG(WARNING) << "Failed to resolve stat " << exe << ": " << ec;
    return std::nullopt;
  }

  return exe;
}

bool is_dir(const std::string &path)
{
  std::error_code ec;
  std::filesystem::path buf{ path };
  return std::filesystem::is_directory(buf, ec);
}

// Check whether 'path' refers to an executable ELF file.
bool is_exe(const std::string &path)
{
  if (auto e_type = is_elf(path)) {
    return e_type == ET_EXEC && has_exec_permission(path);
  }
  return false;
}

std::optional<std::string> abs_path(const std::string &rel_path)
{
  // filesystem::canonical does not work very well with /proc/<pid>/root paths
  // of processes in a different mount namespace (than the one bpftrace is
  // running in), failing during canonicalization. See bpftrace:bpftrace#1595
  static auto re = std::regex("^/proc/\\d+/root/.*");
  if (!std::regex_match(rel_path, re)) {
    try {
      auto p = std::filesystem::path(rel_path);
      return std::filesystem::canonical(std::filesystem::absolute(p)).string();
    } catch (std::filesystem::filesystem_error &) {
      return {};
    }
  } else {
    return rel_path;
  }
}

std::string path_for_pid_mountns(int pid, const std::string &path)
{
  std::ostringstream pid_relative_path;
  char pid_root[64];

  snprintf(pid_root, sizeof(pid_root), "/proc/%d/root", pid);

  if (!path.starts_with(pid_root)) {
    std::string sep = (!path.empty() && path.at(0) == '/') ? "" : "/";
    pid_relative_path << pid_root << sep << path;
  } else {
    // The path is already relative to the pid's root
    pid_relative_path << path;
  }
  return pid_relative_path.str();
}

} // namespace bpftrace::util
