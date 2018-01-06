#pragma once

#include <map>
#include "types.h"

namespace bpftrace {

class Field {
public:
  SizedType type;
  int offset;
};

class Struct
{
public:
  int size;
  std::map<std::string, Field> fields;
};

} // namespace bpftrace
