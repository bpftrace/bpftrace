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
  static int n;
};

} // namespace bpftrace
} // namespace ebpf
