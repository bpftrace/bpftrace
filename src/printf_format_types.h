#include <unordered_map>

#include "types.h"

namespace bpftrace {

// valid printf length + specifier combinations
// it's done like this because as of this writing, C++ doesn't have a builtin way to do
// compile time string concatenation. here is the Python 3 code that generates this map:
// #!/usr/bin/python3
// lengths = ("", "hh", "h", "l", "ll", "j", "z", "t")
// specifiers = ("d", "u", "x", "X", "p")
//
// print("{\"s\", Type::string},")
// print(",\n".join([f"{{\"{l+s}\", Type::integer}}" for l in lengths for s in specifiers]))
const std::unordered_map<std::string, Type> printf_format_types = {
  {"s", Type::string},
  {"c", Type::integer},
  {"d", Type::integer},
  {"u", Type::integer},
  {"x", Type::integer},
  {"X", Type::integer},
  {"p", Type::integer},
  {"hhd", Type::integer},
  {"hhu", Type::integer},
  {"hhx", Type::integer},
  {"hhX", Type::integer},
  {"hhp", Type::integer},
  {"hd", Type::integer},
  {"hu", Type::integer},
  {"hx", Type::integer},
  {"hX", Type::integer},
  {"hp", Type::integer},
  {"ld", Type::integer},
  {"lu", Type::integer},
  {"lx", Type::integer},
  {"lX", Type::integer},
  {"lp", Type::integer},
  {"lld", Type::integer},
  {"llu", Type::integer},
  {"llx", Type::integer},
  {"llX", Type::integer},
  {"llp", Type::integer},
  {"jd", Type::integer},
  {"ju", Type::integer},
  {"jx", Type::integer},
  {"jX", Type::integer},
  {"jp", Type::integer},
  {"zd", Type::integer},
  {"zu", Type::integer},
  {"zx", Type::integer},
  {"zX", Type::integer},
  {"zp", Type::integer},
  {"td", Type::integer},
  {"tu", Type::integer},
  {"tx", Type::integer},
  {"tX", Type::integer},
  {"tp", Type::integer}
};

} // namespace bpftrace
