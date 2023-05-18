#pragma once

#include <string_view>

namespace bpftrace {

// These externs are provided by our build system. See resources/CMakeLists.txt
extern const std::string_view __stddef_max_align_t_h;
extern const std::string_view float_h;
extern const std::string_view limits_h;
extern const std::string_view stdarg_h;
extern const std::string_view stdbool_h;
extern const std::string_view stddef_h;
extern const std::string_view stdint_h;
extern const std::string_view clang_workarounds_h;

} // namespace bpftrace
