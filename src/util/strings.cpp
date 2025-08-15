#include <algorithm>
#include <codecvt>
#include <cstdint>
#include <locale>
#include <sstream>

#include "util/strings.h"

namespace bpftrace::util {

std::vector<std::string> split_string(const std::string &str,
                                      char delimiter,
                                      bool remove_empty)
{
  std::vector<std::string> elems;
  std::stringstream ss(str);
  std::string value;
  while (std::getline(ss, value, delimiter)) {
    if (remove_empty && value.empty())
      continue;

    elems.push_back(value);
  }
  return elems;
}

/// Erase prefix up to the first colon (:) from str and return the prefix
std::string erase_prefix(std::string &str)
{
  std::string prefix = str.substr(0, str.find(':'));
  str.erase(0, prefix.length() + 1);
  return prefix;
}

void erase_parameter_list(std::string &demangled_name)
{
  size_t args_start = std::string::npos;
  ssize_t stack = 0;
  // Look for the parenthesis closing the parameter list, then find
  // the matching parenthesis at the start of the parameter list...
  for (ssize_t it = demangled_name.find_last_of(')'); it >= 0; --it) {
    if (demangled_name[it] == ')')
      stack++;
    if (demangled_name[it] == '(')
      stack--;
    if (stack == 0) {
      args_start = it;
      break;
    }
  }

  // If we found the start of the parameter list,
  // remove the parameters from the match line.
  if (args_start != std::string::npos)
    demangled_name.resize(args_start);
}

std::string str_join(const std::vector<std::string> &list,
                     const std::string &delim)
{
  std::string str;
  bool first = true;
  for (const auto &elem : list) {
    if (first)
      first = false;
    else
      str += delim;

    str += elem;
  }
  return str;
}

std::string hex_format_buffer(const char *buf,
                              size_t size,
                              bool keep_ascii,
                              bool escape_hex)
{
  // Allow enough space for every byte to be sanitized in the form "\x00"
  std::string str((size * 4) + 1, '\0');
  char *s = str.data();

  size_t offset = 0;
  for (size_t i = 0; i < size; i++)
    if (keep_ascii && buf[i] >= 32 && buf[i] <= 126)
      offset += sprintf(s + offset,
                        "%c",
                        (reinterpret_cast<const uint8_t *>(buf))[i]);
    else if (escape_hex)
      offset += sprintf(s + offset,
                        "\\x%02x",
                        (reinterpret_cast<const uint8_t *>(buf))[i]);
    else
      offset += sprintf(s + offset,
                        i == size - 1 ? "%02x" : "%02x ",
                        (reinterpret_cast<const uint8_t *>(buf))[i]);

  // Fit return value to actual length
  str.resize(offset);
  return str;
}

std::string to_lower(const std::string &original)
{
  std::string lower(original);
  std::ranges::transform(lower, lower.begin(), [](unsigned char c) {
    return std::tolower(c);
  });
  return lower;
}

bool is_str_bool_truthy(const std::string &value)
{
  auto val = util::to_lower(value);
  return val == "1" || val == "true" || val == "on" || val == "yes";
}

bool is_str_bool_falsy(const std::string &value)
{
  auto val = util::to_lower(value);
  return val == "0" || val == "false" || val == "off" || val == "no";
}

std::string to_utf8(const std::u32string &str)
{
  std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> conv;
  return conv.to_bytes(str);
}

} // namespace bpftrace::util
