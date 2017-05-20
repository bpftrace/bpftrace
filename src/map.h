#pragma once

#include <map>
#include <string>

namespace ebpf {
namespace bpftrace {

class Map {
public:
  Map(std::string &, int key_size);
  ~Map();
  Map(const Map &) = delete;
  Map& operator=(const Map &) = delete;

  int mapfd_;
  std::string name_;
};

} // namespace bpftrace
} // namespace ebpf
