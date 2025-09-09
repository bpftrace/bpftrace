#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/macro_expansion.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

std::unordered_map<std::string, Macro *> collect_macros(ASTContext &ast)
{
  std::unordered_map<std::string, Macro *> macros;
  for (Macro *macro : ast.root->macros) {
    if (macros.contains(macro->name)) {
      macro->addError() << "Redifinition of macro: " << macro->name;
      return macros;
    }

    std::unordered_set<std::string> seen_mvars;
    std::unordered_set<std::string> seen_mmaps;
    for (const auto &arg : macro->vargs) {
      if (auto *mvar = arg.as<Variable>()) {
        auto inserted = seen_mvars.insert(mvar->ident);
        if (!inserted.second) {
          mvar->addError()
              << "Variable for macro argument has already been used: "
              << mvar->ident;
          return macros;
        }
      } else if (auto *mmap = arg.as<Map>()) {
        auto inserted = seen_mmaps.insert(mmap->ident);
        if (!inserted.second) {
          mmap->addError() << "Map for macro argument has already been used: "
                           << mmap->ident;
          return macros;
        }
      }
    }

    macros[macro->name] = macro;
  }

  return macros;
}

class MacroExpander : public Visitor<MacroExpander> {
public:
  MacroExpander(ASTContext &ast,
                const std::unordered_map<std::string, Macro *> &macros,
                std::string macro_name = "",
                std::vector<std::string> &&macro_stack = {});

  using Visitor<MacroExpander>::visit;

  void visit(AssignVarStatement &assignment);
  void visit(Variable &var);
  void visit(VariableAddr &var_addr);
  void visit(VarDeclStatement &decl);
  void visit(Map &map);
  void visit(Expression &expr);

  std::optional<BlockExpr *> expand(Macro &macro, Call &call);
  std::optional<BlockExpr *> expand(Macro &macro, Identifier &ident);

private:
  ASTContext &ast_;
  const std::unordered_map<std::string, Macro *> &macros_;
  const std::string macro_name_;

  bool is_recursive_call(const std::string &macro_name, const Node &node);
  std::string get_new_var_ident(std::string original_ident);
  bool is_top_level()
  {
    return macro_stack_.empty();
  }

  // Maps of macro map/var names -> callsite map/var names
  std::unordered_map<std::string, std::string> maps_;
  std::unordered_map<std::string, std::string> vars_;
  std::unordered_set<std::string> renamed_vars_;
  std::unordered_map<std::string, Expression> passed_exprs_;
  const std::vector<std::string> macro_stack_;
};

MacroExpander::MacroExpander(
    ASTContext &ast,
    const std::unordered_map<std::string, Macro *> &macros,
    std::string macro_name,
    std::vector<std::string> &&macro_stack)
    : ast_(ast),
      macros_(macros),
      macro_name_(std::move(macro_name)),
      macro_stack_(std::move(macro_stack))
{
}

void MacroExpander::visit(AssignVarStatement &assignment)
{
  if (is_top_level()) {
    visit(assignment.expr);
    return;
  }

  auto *var = assignment.var();

  // Don't rename any variable passed by reference
  if (!vars_.contains(var->ident)) {
    renamed_vars_.insert(var->ident);
  }

  if (std::holds_alternative<VarDeclStatement *>(assignment.var_decl)) {
    visit(std::get<VarDeclStatement *>(assignment.var_decl));
  } else {
    visit(std::get<Variable *>(assignment.var_decl));
  }
  visit(assignment.expr);
}

void MacroExpander::visit(VarDeclStatement &decl)
{
  if (is_top_level()) {
    return;
  }

  auto *var = decl.var;
  if (vars_.contains(var->ident)) {
    decl.addError() << "Variable declaration shadows macro arg " << var->ident;
    return;
  }
  renamed_vars_.insert(var->ident);

  visit(decl.var);
}

void MacroExpander::visit(Variable &var)
{
  if (is_top_level()) {
    return;
  }

  if (auto it = vars_.find(var.ident); it != vars_.end()) {
    var.ident = it->second;
  } else if (renamed_vars_.contains(var.ident)) {
    var.ident = get_new_var_ident(var.ident);
  }
}

void MacroExpander::visit(VariableAddr &var_addr)
{
  visit(var_addr.var);
}

void MacroExpander::visit(Map &map)
{
  if (is_top_level()) {
    return;
  }

  if (auto it = maps_.find(map.ident); it != maps_.end()) {
    map.ident = it->second;
  } else {
    map.addError() << "Unhygienic access to map: " << map.ident
                   << ". Maps must be passed into the macro as arguments.";
  }
}

bool MacroExpander::is_recursive_call(const std::string &macro_name,
                                      const Node &node)
{
  for (size_t i = 0; i < macro_stack_.size(); ++i) {
    if (macro_stack_.at(i) == macro_name) {
      auto &err = node.addError();
      err << "Recursive macro call detected. Call chain: ";
      for (; i < macro_stack_.size(); ++i) {
        err << macro_stack_.at(i) << " > ";
      }
      err << macro_name;
      return true;
    }
  }
  return false;
}

void MacroExpander::visit(Expression &expr)
{
  auto *ident = expr.as<Identifier>();
  auto *call = expr.as<Call>();

  if (!ident && !call) {
    // Recursively expand the new expression, which may again contain macros...
    Visitor<MacroExpander>::visit(expr);
    return;
  }

  if (ident) {
    if (auto it = passed_exprs_.find(ident->ident); it != passed_exprs_.end()) {
      expr = it->second;
      // Create a new expander because we're visiting an expression passed into
      // the macro so it's not part of the surounding macro code and therefore
      // variables, maps, and idents in this expression shouldn't be modified or
      // checked
      MacroExpander expander(ast_, macros_);
      expander.visit(expr);
      return;
    }
  }

  const std::string &name = ident ? ident->ident : call->func;

  if (call) {
    for (auto &varg : call->vargs) {
      visit(varg);
    }
  }

  if (auto it = macros_.find(name); it != macros_.end()) {
    Macro *macro = it->second;

    if (is_recursive_call(name, expr.node())) {
      return;
    }

    auto next_macro_stack = macro_stack_;
    next_macro_stack.push_back(name);

    auto r =
        ident ? MacroExpander(ast_, macros_, name, std::move(next_macro_stack))
                    .expand(*macro, *ident)
              : MacroExpander(ast_, macros_, name, std::move(next_macro_stack))
                    .expand(*macro, *call);
    if (r) {
      expr.value = *r;
    }
  }
}

std::string MacroExpander::get_new_var_ident(std::string original_ident)
{
  return std::string("$$") + macro_name_ + std::string("_") + original_ident;
}

std::optional<BlockExpr *> MacroExpander::expand(Macro &macro, Call &call)
{
  if (macro.vargs.size() != call.vargs.size()) {
    call.addError() << "Call to " << macro.name
                    << "() has the wrong number of arguments. Expected: "
                    << macro.vargs.size() << " but got " << call.vargs.size();
    return std::nullopt;
  }

  for (size_t i = 0; i < macro.vargs.size(); i++) {
    if (auto *mident = macro.vargs.at(i).as<Identifier>()) {
      if (call.vargs.at(i).is<Variable>() || call.vargs.at(i).is<Map>()) {
        // Wrap variables and maps in a block to avoid mutation.
        passed_exprs_[mident->ident] = ast_.make_node<BlockExpr>(
            StatementList({}),
            clone(ast_, call.vargs.at(i), call.vargs.at(i).loc()),
            Location(call.loc));
      } else {
        passed_exprs_[mident->ident] = clone(ast_,
                                             call.vargs.at(i),
                                             call.vargs.at(i).loc());
      }
    } else if (auto *mvar = macro.vargs.at(i).as<Variable>()) {
      if (auto *cvar = call.vargs.at(i).as<Variable>()) {
        vars_[mvar->ident] = cvar->ident;
      } else if (call.vargs.at(i).is<Map>()) {
        call.addError() << "Mismatched arg. " << macro.name
                        << "() expects a variable for arg " << mvar->ident
                        << " but got a map.";
      } else {
        call.addError() << "Mismatched arg. " << macro.name
                        << "() expects a variable for arg " << mvar->ident
                        << " but got an expression.";
      }
    } else if (auto *mmap = macro.vargs.at(i).as<Map>()) {
      if (auto *cmap = call.vargs.at(i).as<Map>()) {
        maps_[mmap->ident] = cmap->ident;
      } else if (call.vargs.at(i).is<Variable>()) {
        call.addError() << "Mismatched arg. " << macro.name
                        << "() expects a map for arg " << mmap->ident
                        << " but got a variable.";
      } else {
        call.addError() << "Mismatched arg. " << macro.name
                        << "() expects a map for arg " << mmap->ident
                        << " but got an expression.";
      }
    }
  }

  auto *cloned_block = clone(ast_, macro.block, call.loc);
  visit(cloned_block);
  return cloned_block;
}

std::optional<BlockExpr *> MacroExpander::expand(Macro &macro,
                                                 Identifier &ident)
{
  if (!macro.vargs.empty()) {
    ident.addError() << "Call to " << macro.name
                     << "() has the wrong number of arguments. Expected: "
                     << macro.vargs.size() << " but got 0.";
    return std::nullopt;
  }

  auto *cloned_block = clone(ast_, macro.block, ident.loc);
  visit(cloned_block);
  return cloned_block;
}

Pass CreateMacroExpansionPass()
{
  auto fn = [](ASTContext &ast) {
    auto macros = collect_macros(ast);
    if (ast.diagnostics().ok()) {
      MacroExpander expander(ast, macros);
      expander.visit(ast.root);
    }
  };

  return Pass::create("MacroExpansion", fn);
}

} // namespace bpftrace::ast
