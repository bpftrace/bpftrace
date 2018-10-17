#pragma once

#include "utils.h"

namespace bpftrace {

inline std::string GetProviderFromPath(std::string path) {
  int i = path.rfind("/");
  return (i != std::string::npos) ? path.substr(i + 1) : path;
}

} // namespace bpftrace
