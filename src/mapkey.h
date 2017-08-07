#pragma once

#include <string>
#include <vector>

#include "types.h"

namespace bpftrace {

class BPFtrace;

class MapKey
{
public:
  std::vector<SizedType> args_;

  bool operator!=(const MapKey &k) const;

  size_t size() const;
  std::string argument_type_list() const;
  std::string argument_value_list(BPFtrace &bpftrace,
      const std::vector<uint8_t> &data) const;

private:
  static std::string argument_value(BPFtrace &bpftrace,
      const SizedType &arg,
      const void *data);
};

} // namespace bpftrace
