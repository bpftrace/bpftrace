#include <unordered_map>
#include <unordered_set>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/macro_expansion.h"
#include "ast/visitor.h"

#include "log.h"

namespace bpftrace::ast {

// Specialies a macro body for its call site.
class MacroSpecializer : public Visitor<MacroSpecializer> {
public:
  MacroSpecializer(ASTContext &ast);

  using Visitor<MacroSpecializer>::visit;
  void visit(Variable &var);
  void visit(Map &map);

  Expression *specialize(Macro &macro, const Call &call);

private:
  ASTContext &ast_;

  // Maps of macro map/var names -> callsite map/var names
  std::unordered_map<std::string, std::string> maps_;
  std::unordered_map<std::string, std::string> vars_;
};

// Expands macros into their call sites.
class MacroExpansion : public Visitor<MacroExpansion> {
public:
  MacroExpansion(ASTContext &ast);

  using Visitor<MacroExpansion>::replace;
  Expression *replace(Call *call, void *ret);

  void run();

private:
  ASTContext &ast_;
  std::unordered_map<std::string, Macro *> macros_;
  std::unordered_set<std::string> called_;
};

MacroSpecializer::MacroSpecializer(ASTContext &ast) : ast_(ast)
{
}

void MacroSpecializer::visit(Variable &var)
{
  if (auto it = vars_.find(var.ident); it != vars_.end()) {
    var.ident = it->second;
  } else {
    var.addError() << "Unhygienic access to variable";
  }
}

void MacroSpecializer::visit(Map &map)
{
  if (auto it = maps_.find(map.ident); it != maps_.end()) {
    map.ident = it->second;
  } else {
    map.addError() << "Unhygienic access to map";
  }
}

Expression *MacroSpecializer::specialize(Macro &macro, const Call &call)
{
  maps_.clear();
  vars_.clear();

  if (macro.args.size() != call.vargs.size()) {
    call.addError() << "Call to macro has wrong number arguments: "
                    << macro.args.size() << "!=" << call.vargs.size();
    return nullptr;
  }

  for (size_t i = 0; i < call.vargs.size(); i++) {
    Expression *marg = macro.args[i];
    Expression *carg = call.vargs[i];

    if (auto *cvar = dynamic_cast<Variable *>(carg)) {
      if (auto *mvar = dynamic_cast<Variable *>(marg)) {
        vars_[mvar->ident] = cvar->ident;
      } else {
        call.addError() << "Mismatched arg=" << i << " to macro call";
      }
    } else if (auto *cmap = dynamic_cast<Map *>(carg)) {
      if (auto *mmap = dynamic_cast<Map *>(marg)) {
        maps_[mmap->ident] = cmap->ident;
      } else {
        call.addError() << "Mismatched arg=" << i << " to macro call";
      }
    } else {
      LOG(BUG) << "Parser let in a non-var and non-map macro argument";
    }
  }

  // TODO: clone the macro body
  visit(macro.expr);

  return ast_.diagnostics().ok() ? macro.expr : nullptr;
}

MacroExpansion::MacroExpansion(ASTContext &ast) : ast_(ast)
{
}

void MacroExpansion::run()
{
  for (Macro *macro : ast_.root->macros) {
    macros_[macro->name] = macro;
  }

  visit(ast_.root);
}

Expression *MacroExpansion::replace(Call *call, [[maybe_unused]] void *ret)
{
  if (auto it = macros_.find(call->func); it != macros_.end()) {
    if (called_.contains(call->func)) {
      call->addError() << "The PoC can only handle a single call of: "
                       << call->func;
      return nullptr;
    } else {
      called_.insert(call->func);
    }

    Macro *macro = it->second;
    Expression *expr = MacroSpecializer(ast_).specialize(*macro, *call);
    if (expr) {
      return expr;
    } else {
      call->addError() << "Failed to specialize macro: " << call->func;
      return call;
    }
  }

  return call;
}

Pass CreateMacroExpansionPass()
{
  auto fn = [](ASTContext &ast) {
    MacroExpansion expander(ast);
    expander.run();
  };

  return Pass::create("MacroExpansion", fn);
}

} // namespace bpftrace::ast
