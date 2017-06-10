#pragma once

#include <string>
#include <vector>

#include "types.h"

namespace bpftrace {

class MapKey
{
public:
  std::vector<MapKeyArgument> args_;

  bool operator!=(const MapKey &k) const;

  size_t size() const;
  std::string argument_type_list() const;
  std::string argument_value_list(const std::vector<uint8_t> &data) const;

private:
  std::string argument_value(const MapKeyArgument &arg, const void *data) const;
};

} // namespace bpftrace
