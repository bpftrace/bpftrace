#pragma once

#include <string>
#include <vector>

namespace bpftrace::util {

// trim from end of string (right)
inline std::string &rtrim(std::string &s)
{
  s.erase(s.find_last_not_of(" ") + 1);
  return s;
}

// trim from beginning of string (left)
inline std::string &ltrim(std::string &s)
{
  s.erase(0, s.find_first_not_of(" "));
  return s;
}

// trim from both ends of string (right then left)
inline std::string &trim(std::string &s)
{
  return ltrim(rtrim(s));
}

std::vector<std::string> split_string(const std::string &str,
                                      char delimiter,
                                      bool remove_empty = false);

std::string str_join(const std::vector<std::string> &list,
                     const std::string &delim);

std::string erase_prefix(std::string &str);
void erase_parameter_list(std::string &demangled_name);

std::string hex_format_buffer(const char *buf,
                              size_t size,
                              bool keep_ascii = true,
                              bool escape_hex = true);

} // namespace bpftrace::util
