#pragma once

#include <map>
#include <string>

namespace ebpf {
namespace bpftrace {

class Map {
public:
  Map();
  ~Map();

  int mapfd_;
};

} // namespace bpftrace
} // namespace ebpf
