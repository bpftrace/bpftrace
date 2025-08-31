#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream> // for std::ostringstream

#include "util/bpf_names.h"

namespace bpftrace::util {

// BPF verifier rejects programs with names containing certain characters, use
// this function to replace every character not valid for C identifiers by '_'
std::string sanitise_bpf_program_name(const std::string &name)
{
  std::string sanitised_name = name;
  std::ranges::replace_if(
      sanitised_name,

      [](char c) { return !isalnum(c) && c != '_'; },
      '_');

  // Kernel KSYM_NAME_LEN is 128 until 6.1
  // If we'll exceed the limit, hash the string and cap at 127 (+ null byte).
  if (sanitised_name.size() > 127) {
    size_t hash = std::hash<std::string>{}(sanitised_name);

    // std::hash returns size_t, so we reserve 2*sizeof(size_t)+1 characters
    std::ostringstream os;
    os << sanitised_name.substr(0, 127 - (2 * sizeof(hash)) - 1) << '_'
       << std::setfill('0') << std::hex << hash;
    sanitised_name = os.str();
  }
  return sanitised_name;
}

} // namespace bpftrace::util
