#pragma once

#include <string>

#include "mapkey.h"
#include "types.h"

#include "libbpf.h"

namespace bpftrace {

class IMap {
public:
  virtual ~IMap() { }
  IMap() { }
  IMap(const IMap &) = delete;
  IMap& operator=(const IMap &) = delete;

  int mapfd_;
  std::string name_;
  SizedType type_;
  MapKey key_;

  // used by lhist(). TODO: move to separate Map object.
  int lqmin;
  int lqmax;
  int lqstep;
};

} // namespace bpftrace
