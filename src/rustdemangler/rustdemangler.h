#pragma once

#include <string>

namespace bpftrace {

// Demangle a mangled rust symbol name.
std::string rustdemangle(const char* mangled);

} // namespace bpftrace
