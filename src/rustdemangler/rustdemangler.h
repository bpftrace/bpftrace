#pragma once

namespace bpftrace {

// Demangle a mangled rust symbol name
//
// Note: callee `free()`ed
char* rustdemangle(const char* mangled);

} // namespace bpftrace
