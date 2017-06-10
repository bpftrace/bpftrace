#pragma once

#include <map>
#include <string>
#include <vector>

#include "mapkey.h"
#include "types.h"

namespace bpftrace {

class Map {
public:
  Map(std::string &name, Type type, MapKey key);
  ~Map();
  Map(const Map &) = delete;
  Map& operator=(const Map &) = delete;

  int mapfd_;
  std::string name_;
  Type type_;
  MapKey key_;
};

} // namespace bpftrace
