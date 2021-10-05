#pragma once

namespace bpftrace {

// Demangle a mangled C++ symbol name
//
// Note: callee `free()`ed
char* cxxdemangle(const char* mangled);

} // namespace bpftrace
