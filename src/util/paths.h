#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace bpftrace::util {

std::vector<std::string> resolve_binary_path(
    const std::string &cmd,
    std::optional<int> pid = std::nullopt);

// Tries to find a file in $PATH.
std::optional<std::filesystem::path> find_in_path(std::string_view name);
// Finds a file in the same directory as running binary.
std::optional<std::filesystem::path> find_near_self(std::string_view name);

unsigned long file_ino(const std::string &path);

bool is_dir(const std::string &path);
bool is_exe(const std::string &path);

std::optional<std::string> abs_path(const std::string &rel_path);

std::string path_for_pid_mountns(int pid, const std::string &path);

bool path_ends_with(const std::filesystem::path &path,
                    const std::filesystem::path &pattern);

} // namespace bpftrace::util
