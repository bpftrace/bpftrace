#pragma once

#include <map>
#include <string>

namespace bpftrace::stdlib {

class Stdlib {
public:
  // This is constructed automatically from a generated `stdlib.cpp`.
  static const std::map<std::string, std::string_view> c_files;
  static const std::map<std::string, std::string_view> bt_files;
  static const std::map<std::string, std::string> macro_to_file;
};

} // namespace bpftrace::stdlib
