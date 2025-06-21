#pragma once

#include <algorithm>
#include <string>

namespace bpftrace::util {

// TypeName is used as a template parameter to work around restrictions on
// literals passed as template parameters. This is essentially a string
// literal used to name the type.
template <size_t N>
struct TypeName {
  constexpr TypeName(const char (&s)[N])
  {
    std::copy_n(s, N, value);
  }
  char value[N];
  std::string str() const
  {
    // N.B. the value here includes the trailing zero, so when constructing a
    // string we truncate this zero.
    return std::string(value, sizeof(value) - 1);
  }
};

} // namespace bpftrace::util
