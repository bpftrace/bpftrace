#pragma once

#include <map>
#include <string>

namespace ebpf {
namespace bpftrace {

class Map {
public:
  explicit Map(std::string &);
  ~Map();

  int mapfd_;
  std::string name_;
};

} // namespace bpftrace
} // namespace ebpf
