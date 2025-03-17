#pragma once

#include <string>

namespace bpftrace {

const std::string &is_deprecated(const std::string &str);
bool is_unsafe_func(const std::string &func_name);
bool is_compile_time_func(const std::string &func_name);
bool is_supported_lang(const std::string &lang);
bool is_type_name(std::string_view str);

} // namespace bpftrace
