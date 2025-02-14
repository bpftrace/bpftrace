#pragma once

#include <string>

namespace bpftrace {

// Demangle a mangled C++ symbol name.
std::string cxxdemangle(const char* mangled);

} // namespace bpftrace
