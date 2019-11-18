#pragma once

#include <map>
#include "types.h"

namespace bpftrace {

struct Field {
  SizedType type;
  int offset;
};

using FieldsMap = std::map<std::string, Field>;

struct Struct
{
  int size;
  FieldsMap fields;
};

} // namespace bpftrace
