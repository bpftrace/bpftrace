#pragma once

#include <map>
#include <string>
#include <vector>

#include "types.h"

namespace bpftrace {

class Map {
public:
  Map(std::string &, Type type, std::vector<Type> &args);
  ~Map();
  Map(const Map &) = delete;
  Map& operator=(const Map &) = delete;

  int mapfd_;
  std::string name_;
  Type type_;
  std::vector<Type> args_;
};

} // namespace bpftrace
