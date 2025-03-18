#include <unordered_set>
#include <vector>

#include "ast/helpers.h"
#include "log.h"

namespace bpftrace {

struct DeprecatedName {
  std::string old_name;
  std::string new_name;
  bool show_warning = true;
  bool replace_by_new_name = true;

  bool matches(const std::string &name) const
  {
    // We allow a prefix match to match against builtins with number (argX)
    if (old_name.back() == '*') {
      std::string_view old_name_view{ old_name.c_str(), old_name.size() - 1 };
      return name.rfind(old_name_view) == 0;
    }

    return name == old_name;
  }
};

static std::vector<DeprecatedName> DEPRECATED_LIST = {
  { .old_name = "sarg*",
    .new_name = "*(reg(\"sp\") + <stack_offset>)",
    .show_warning = true,
    .replace_by_new_name = false }
};

static std::unordered_set<std::string> UNSAFE_BUILTIN_FUNCS = {
  "system",
  "signal",
  "override",
};

static std::unordered_set<std::string> COMPILE_TIME_FUNCS = { "cgroupid" };

static std::unordered_set<std::string> UPROBE_LANGS = { "cpp" };

const std::string &is_deprecated(const std::string &str)
{
  for (auto &item : DEPRECATED_LIST) {
    if (!item.matches(str)) {
      continue;
    }

    if (item.show_warning) {
      LOG(WARNING) << item.old_name
                   << " is deprecated and will be removed in the future. Use "
                   << item.new_name << " instead.";
      item.show_warning = false;
    }

    if (item.replace_by_new_name) {
      return item.new_name;
    } else {
      return str;
    }
  }

  return str;
}

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
  return str.starts_with("struct ") || str.starts_with("union ") ||
         str.starts_with("enum ");
}

} // namespace bpftrace
