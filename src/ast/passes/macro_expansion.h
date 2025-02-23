#pragma once

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "ast/visitor.h"

#include <unordered_map>

namespace bpftrace {
namespace ast {

// Expands macros into their call sites.
class MacroExpansion : public Visitor<MacroExpansion> {
public:
  MacroExpansion(ASTContext &ctx);

  using Visitor<MacroExpansion>::replace;
  Expression *replace(Call *call, void *);

  void run();

private:
  std::unordered_map<std::string, Macro *> macros_;
};

Pass CreateMacroExpansionPass();

} // namespace ast
} // namespace bpftrace
