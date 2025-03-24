#pragma once

#include <map>
#include <string>

namespace bpftrace::stdlib {

class Stdlib {
  // files is the set of files embedded in the standard library.
  static const std::map<std::string, std::string> files;
};

} // namespace bpftrace::stdlib
