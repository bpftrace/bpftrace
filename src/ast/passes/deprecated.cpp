#include <vector>

#include "ast/passes/deprecated.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class DeprecatedAnalyser : public Visitor<DeprecatedAnalyser> {
public:
  using Visitor<DeprecatedAnalyser>::visit;
  void visit(Builtin &builtin);
  void visit(Call &call);
};

struct DeprecatedName {
  std::string old_name;
  std::string new_name;

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

} // namespace

static void check(const std::vector<DeprecatedName> &list,
                  const std::string &ident,
                  Node &node)
{
  for (const auto &item : list) {
    if (!item.matches(ident)) {
      continue;
    }

    auto &warn = node.addWarning();
    warn << item.old_name
         << " is deprecated and will be removed in the future.";
    warn.addHint() << "Use " << item.new_name << " instead.";
  }
}

static std::vector<DeprecatedName> DEPRECATED_BUILTINS = {
  {
      .old_name = "sarg*",
      .new_name = "*(reg(\"sp\") + <stack_offset>)",
  },
};

void DeprecatedAnalyser::visit(Builtin &builtin)
{
  check(DEPRECATED_BUILTINS, builtin.ident, builtin);
}

static std::vector<DeprecatedName> DEPRECATED_CALLS = {};

void DeprecatedAnalyser::visit(Call &call)
{
  check(DEPRECATED_CALLS, call.func, call);
}

Pass CreateDeprecatedPass()
{
  auto fn = [](ASTContext &ast) {
    DeprecatedAnalyser deprecated;
    deprecated.visit(ast.root);
  };

  return Pass::create("Deprecated", fn);
}

} // namespace bpftrace::ast
