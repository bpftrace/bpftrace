#pragma once

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "ast/visitor.h"

#include <iostream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace bpftrace {
namespace ast {

// Specialies a macro body for its call site.
class MacroSpecializer : public Visitor<MacroSpecializer> {
public:
  MacroSpecializer(ASTContext &ctx, std::ostream &out);

  using Visitor<MacroSpecializer>::visit;
  void visit(AssignVarStatement &assignment);
  void visit(Variable &var);
  void visit(Map &map);

  Expression *specialize(Macro &macro, const Call &call);

private:
  std::ostream &out_;
  std::ostringstream err_;

  // Maps of macro map/var names -> callsite map/var names
  std::unordered_map<std::string, std::string> maps_;
  std::unordered_map<std::string, std::string> vars_;
};

// Expands macros into their call sites.
class MacroExpansion : public Visitor<MacroExpansion> {
public:
  MacroExpansion(ASTContext &ctx, std::ostream &out = std::cerr);

  using Visitor<MacroExpansion>::replace;
  Expression *replace(Call *call, void *);

  int run();

private:
  std::ostream &out_;
  std::ostringstream err_;

  std::unordered_set<std::string> called_;
  std::unordered_map<std::string, Macro *> macros_;
};

Pass CreateMacroExpansionPass();

} // namespace ast
} // namespace bpftrace
