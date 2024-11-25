#pragma once

#include <filesystem>
#include <string>

namespace bpftrace {

/**
 * TODO
 */
struct Import {
public:
  Import(std::string name, std::filesystem::path path)
      : name_(std::move(name)), path_(std::move(path))
  {
  }
  Import(std::string name,
         std::filesystem::path path,
         std::optional<std::filesystem::path> user_path)
      : name_(std::move(name)), path_(std::move(path)), user_path_(user_path)
  {
  }

  const std::string &name() const
  {
    return name_;
  }
  const std::filesystem::path &path() const
  {
    return path_;
  }
  const std::optional<std::filesystem::path> &user_path() const
  {
    return user_path_;
  }

private:
  std::string name_;
  std::filesystem::path path_;
  std::optional<std::filesystem::path> user_path_;
};

} // namespace bpftrace
