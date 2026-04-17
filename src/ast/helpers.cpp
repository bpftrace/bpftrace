#include <unordered_set>

#include "ast/helpers.h"
#include "log.h"
#include "types.h"

namespace bpftrace {

// N.B. there are other unsafe builtins but they are being checked
// inside the macros themselves
static std::unordered_set<std::string> UNSAFE_BUILTIN_FUNCS = {
  "system",
};

static std::unordered_set<std::string> COMPILE_TIME_FUNCS = { "cgroupid" };

static std::unordered_set<std::string> UPROBE_LANGS = { "cpp" };

bool is_unsafe_func(const std::string &func_name)
{
  return UNSAFE_BUILTIN_FUNCS.contains(func_name);
}

bool is_compile_time_func(const std::string &func_name)
{
  return COMPILE_TIME_FUNCS.contains(func_name);
}

bool is_supported_lang(const std::string &lang)
{
  return UPROBE_LANGS.contains(lang);
}

bool is_type_name(std::string_view str)
{
  return str.starts_with(STRUCT_PREFIX) || str.starts_with(UNION_PREFIX) ||
         str.starts_with(ENUM_PREFIX);
}

} // namespace bpftrace
