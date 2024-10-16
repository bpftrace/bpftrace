#pragma once

#include <map>
#include <string>

namespace bpftrace {

enum Kfunc {};

static const std::map<Kfunc, std::string> KFUNC_NAME_MAP = {};

inline const std::string &kfunc_name(enum Kfunc kfunc)
{
  return KFUNC_NAME_MAP.at(kfunc);
}

} // namespace bpftrace
