#include <algorithm>
#include <set>
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

static std::vector<std::string> UNSAFE_BUILTIN_FUNCS = {
  "system",
  "signal",
  "override",
};

static std::vector<std::string> COMPILE_TIME_FUNCS = { "cgroupid" };

static std::vector<std::string> UPROBE_LANGS = { "cpp" };

static const std::set<std::string> RECURSIVE_KERNEL_FUNCS = {
  "vmlinux:_raw_spin_lock",
  "vmlinux:_raw_spin_lock_irqsave",
  "vmlinux:_raw_spin_unlock_irqrestore",
  "vmlinux:queued_spin_lock_slowpath",
};

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
  return std::ranges::any_of(UNSAFE_BUILTIN_FUNCS,

                             [&](const auto &cand) {
                               return func_name == cand;
                             });
}

bool is_compile_time_func(const std::string &func_name)
{
  return std::ranges::any_of(COMPILE_TIME_FUNCS,

                             [&](const auto &cand) {
                               return func_name == cand;
                             });
}

bool is_supported_lang(const std::string &lang)
{
  return std::ranges::any_of(UPROBE_LANGS,

                             [&](const auto &cand) { return lang == cand; });
}

bool is_type_name(std::string_view str)
{
  return str.starts_with("struct ") || str.starts_with("union ") ||
         str.starts_with("enum ");
}

// Attaching to these kernel functions with fentry/fexit (kfunc/kretfunc)
// could lead to a recursive loop and kernel crash so we need additional
// generated BPF code to protect against this if one of these are being
// attached to.
bool is_recursive_func(const std::string &func_name)
{
  return RECURSIVE_KERNEL_FUNCS.find(func_name) != RECURSIVE_KERNEL_FUNCS.end();
}

} // namespace bpftrace
