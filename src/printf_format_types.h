#pragma once
#include <unordered_map>

#include "types.h"

namespace bpftrace {

// clang-format off

// valid printf length + specifier combinations
// it's done like this because as of this writing, C++ doesn't have a builtin way to do
// compile time string concatenation. here is the Python 3 code that generates this map:
// #!/usr/bin/python3
// lengths = ("", "hh", "h", "l", "ll", "j", "z", "t")
// specifiers = ("d", "u", "o", "x", "X", "p")
//
// print("{\"s\", Type::string},")
// print("{\"r\", Type::buffer},")
// print("{\"c\", Type::integer},")
// print(",\n".join([f"{{\"{l+s}\", Type::integer}}" for l in lengths for s in specifiers]))
const std::unordered_map<std::string, Type> printf_format_types = {
  {"s", Type::string},
  {"r", Type::buffer},
  {"rx", Type::buffer},
  {"c", Type::integer},
  {"d", Type::integer},
  {"u", Type::integer},
  {"o", Type::integer},
  {"x", Type::integer},
  {"X", Type::integer},
  {"p", Type::integer},
  {"hhd", Type::integer},
  {"hhu", Type::integer},
  {"hho", Type::integer},
  {"hhx", Type::integer},
  {"hhX", Type::integer},
  {"hhp", Type::integer},
  {"hd", Type::integer},
  {"hu", Type::integer},
  {"ho", Type::integer},
  {"hx", Type::integer},
  {"hX", Type::integer},
  {"hp", Type::integer},
  {"ld", Type::integer},
  {"lu", Type::integer},
  {"lo", Type::integer},
  {"lx", Type::integer},
  {"lX", Type::integer},
  {"lp", Type::integer},
  {"lld", Type::integer},
  {"llu", Type::integer},
  {"llo", Type::integer},
  {"llx", Type::integer},
  {"llX", Type::integer},
  {"llp", Type::integer},
  {"jd", Type::integer},
  {"ju", Type::integer},
  {"jo", Type::integer},
  {"jx", Type::integer},
  {"jX", Type::integer},
  {"jp", Type::integer},
  {"zd", Type::integer},
  {"zu", Type::integer},
  {"zo", Type::integer},
  {"zx", Type::integer},
  {"zX", Type::integer},
  {"zp", Type::integer},
  {"td", Type::integer},
  {"tu", Type::integer},
  {"to", Type::integer},
  {"tx", Type::integer},
  {"tX", Type::integer},
  {"tp", Type::integer}
};

// clang-format on

} // namespace bpftrace
