#include <algorithm>
#include <cstdint>
#include <sstream>

#include "util/result.h"
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

Result<std::vector<std::string>> split_string_quotes(const std::string &str)
{
  std::vector<std::string> args;
  std::string current;
  bool in_quotes = false;
  char quote_char = '\0';
  bool has_token = false;

  size_t i = 0;
  while (i < str.size()) {
    char c = str[i];

    if (in_quotes) {
      if (c == quote_char) {
        // Closing quote
        in_quotes = false;
        quote_char = '\0';
        i++;
      } else if (quote_char == '"' && c == '\\' && i + 1 < str.size()) {
        char next = str[i + 1];
        // POSIX rule: inside double quotes, \ only escapes ", \, $, `, and \n
        if (next == '"' || next == '\\' || next == '$' || next == '`' ||
            next == '\n') {
          current += next;
          i += 2;
        } else {
          current += c;
          i++;
        }
      } else {
        current += c;
        i++;
      }
    } else {
      if (c == '\'' || c == '"') {
        in_quotes = true;
        quote_char = c;
        has_token = true;
        i++;
      } else if (c == '\\') {
        // Outside quotes: backslash escapes the following character
        if (i + 1 < str.size()) {
          current += str[i + 1];
          has_token = true;
          i += 2;
        } else {
          return make_error<SystemError>(
              "Trailing backslash in command string: " + str);
        }
      } else if (std::isspace(static_cast<unsigned char>(c))) {
        if (has_token) {
          args.push_back(std::move(current));
          current.clear();
          has_token = false;
        }
        i++;
      } else {
        current += c;
        has_token = true;
        i++;
      }
    }
  }

  if (in_quotes) {
    return make_error<SystemError>("Unclosed quote in command string: " + str);
  }

  if (has_token) {
    args.push_back(std::move(current));
  }

  return args;
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

// Replace any number of consecutive spaces at any position in a string with a
// single space, while removing all leading and trailing spaces.
// This function will create a new string.
std::string normalize_whitespace(const std::string &input)
{
  std::string copy = input;

  trim(copy);

  auto unique_end =
      std::ranges::unique(copy.begin(), copy.end(), [](char l, char r) {
        return std::isspace(l) && std::isspace(r);
      }).begin();
  copy.erase(unique_end, copy.end());

  return copy;
}

} // namespace bpftrace::util
