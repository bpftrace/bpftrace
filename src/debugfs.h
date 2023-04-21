#pragma once

#include <string>

namespace bpftrace {
namespace debugfs {

std::string path();

std::string path(const std::string &file);

inline std::string kprobes_blacklist()
{
  return path("kprobes/blacklist");
}

} // namespace debugfs
} // namespace bpftrace
