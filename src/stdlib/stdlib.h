#pragma once

#include <map>
#include <string>

namespace bpftrace::stdlib {

class Stdlib {
public:
  // files is the set of files embedded in the standard library.
  //
  // This is constructed automatically from a generated `stdlib.cpp`.
  static const std::map<std::string, std::string_view> files;
};

} // namespace bpftrace::stdlib
