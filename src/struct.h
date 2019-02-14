#pragma once

#include <map>
#include "types.h"

namespace bpftrace {

class Field {
public:
  SizedType type;
  int offset;
};

using FieldsMap = std::map<std::string, Field>;

class Struct
{
public:
  int size;
  FieldsMap fields;
};

} // namespace bpftrace
