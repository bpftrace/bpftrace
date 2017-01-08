#pragma once

#include <map>
#include <memory>
#include <vector>

#include "map.h"

namespace ebpf {
namespace bpftrace {

enum class Type
{
  none,
  integer,
  quantize,
  count,
};

std::string typestr(Type t);

class BPFtrace
{
public:
  std::map<std::string, Type> map_val_;
  std::map<std::string, std::vector<Type>> map_args_;
  std::map<std::string, std::unique_ptr<ebpf::bpftrace::Map>> maps_;
};

} // namespace bpftrace
} // namespace ebpf
