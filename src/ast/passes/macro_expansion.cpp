#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/macro_expansion.h"
#include "ast/visitor.h"
#include "bpftrace.h"

#include "log.h"

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
                std::string macro_name,
                const std::unordered_map<std::string, Macro *> &macros,
                std::vector<std::string> &&macro_stack);

  using Visitor<MacroExpander>::visit;

  void visit(AssignVarStatement &assignment);
  void visit(Variable &var);
  void visit(Map &map);
  void visit(Expression &expr);
  // We can't add extra params with default values to the standard `visit`
  // because it then becomes ambiguous
  void replace_macro_call(Expression &expr, bool block_ok = false);
  void visit(Statement &stmt);

  std::optional<BlockExpr *> expand(Macro &macro, Call &call);
  std::optional<BlockExpr *> expand(Macro &macro, Identifier &ident);
  std::optional<BlockExpr *> make_block_expr(Macro &macro,
                                             StatementList &stmt_list,
                                             const Location &loc);

private:
  ASTContext &ast_;
  const std::string macro_name_;
  const std::unordered_map<std::string, Macro *> &macros_;

  bool is_recursive_call(const std::string &macro_name, const Node &node);
  std::string get_new_var_ident(std::string original_ident);
  bool is_top_level()
  {
    return macro_stack_.empty();
  }

  // Maps of macro map/var names -> callsite map/var names
  std::unordered_map<std::string, std::string> maps_;
  std::unordered_map<std::string, std::string> vars_;
  std::unordered_set<Variable *> temp_vars_;
  std::unordered_map<std::string, Call *> arg_vars_no_mutation_;
  const std::vector<std::string> macro_stack_;
};

MacroExpander::MacroExpander(
    ASTContext &ast,
    std::string macro_name,
    const std::unordered_map<std::string, Macro *> &macros,
    std::vector<std::string> &&macro_stack)
    : ast_(ast),
      macro_name_(std::move(macro_name)),
      macros_(macros),
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
  if (temp_vars_.contains(var)) {
    // Don't change variable names if this is a variable assignment
    // that we created to represent the passed in expression e.g.
    // macro add_one($x) { $x + 1 } begin { $a = 1; print(add_one($a + 1)); }
    // will become
    // begin { $a = 1; print({let $$add_one_$a = $a + 1; $$add_one_$a + 1}); }
    return;
  }

  if (auto it = arg_vars_no_mutation_.find(var->ident);
      it != arg_vars_no_mutation_.end()) {
    it->second->addError()
        << "Macro '" << macro_stack_.back() << "' assigns to parameter '"
        << var->ident << "', meaning it expects a variable, not an expression.";
    return;
  }

  if (std::holds_alternative<VarDeclStatement *>(assignment.var_decl)) {
    visit(std::get<VarDeclStatement *>(assignment.var_decl));
  } else {
    visit(std::get<Variable *>(assignment.var_decl));
  }
  visit(assignment.expr);
}

void MacroExpander::visit(Variable &var)
{
  if (is_top_level()) {
    return;
  }

  if (auto it = vars_.find(var.ident); it != vars_.end()) {
    var.ident = it->second;
  } else if (!temp_vars_.contains(&var)) {
    var.ident = get_new_var_ident(var.ident);
  }
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

void MacroExpander::replace_macro_call(Expression &expr, bool block_ok)
{
  auto *ident = expr.as<Identifier>();
  auto *call = expr.as<Call>();

  if (!ident && !call) {
    // Recursively expand the new expression, which may again contain macros...
    Visitor<MacroExpander>::visit(expr);
    return;
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

    if (std::holds_alternative<Block *>(macro->block) && !block_ok) {
      auto &err = expr.node().addError();
      err << "Macro '" << name
          << "' expanded to a block instead of a block "
             "expression. Try removing the semicolon from the "
             "end of the last statement in the macro body.";
      return;
    }

    auto next_macro_stack = macro_stack_;
    next_macro_stack.push_back(name);

    auto r =
        ident ? MacroExpander(ast_, name, macros_, std::move(next_macro_stack))
                    .expand(*macro, *ident)
              : MacroExpander(ast_, name, macros_, std::move(next_macro_stack))
                    .expand(*macro, *call);
    if (r) {
      expr.value = *r;
    }
  }
}

void MacroExpander::visit(Expression &expr)
{
  replace_macro_call(expr);
}

void MacroExpander::visit(Statement &stmt)
{
  auto *expr_stmt = stmt.as<ExprStatement>();
  if (!expr_stmt) {
    Visitor<MacroExpander>::visit(stmt);
    return;
  }

  replace_macro_call(expr_stmt->expr, true);
}

std::string MacroExpander::get_new_var_ident(std::string original_ident)
{
  return std::string("$$") + macro_name_ + std::string("_") + original_ident;
}

std::optional<BlockExpr *> MacroExpander::make_block_expr(
    Macro &macro,
    StatementList &stmt_list,
    const Location &loc)
{
  Expression macro_expr;

  if (std::holds_alternative<Block *>(macro.block)) {
    auto *bare_block = std::get<Block *>(macro.block);
    // Since this always evaluates to a BlockExpr we insert a unused
    // final expression. This shouldn't ever be an issue as we have
    // a check above to ensure that macro bodies that are blocks
    // never get used in place of block expressions, e.g., this is not legal
    // because there is a trailing semi-colon in the macro body:
    // `macro add_one($x) { $x + 1; } begin { $x = 1; $y = add_one($x);`
    macro_expr = ast_.make_node<Boolean>(false, Location(macro.loc));
    for (auto expr : bare_block->stmts) {
      stmt_list.push_back(clone(ast_, expr, loc));
    }
  } else {
    auto *block_expr = std::get<BlockExpr *>(macro.block);
    macro_expr = clone(ast_, block_expr->expr, loc);
    for (auto expr : block_expr->stmts) {
      stmt_list.push_back(clone(ast_, expr, loc));
    }
  }

  auto *cloned_block = ast_.make_node<BlockExpr>(std::move(stmt_list),
                                                 macro_expr,
                                                 Location(macro.loc));

  visit(cloned_block);

  if (ast_.diagnostics().ok()) {
    return cloned_block;
  }

  return std::nullopt;
}

std::optional<BlockExpr *> MacroExpander::expand(Macro &macro, Call &call)
{
  if (macro.vargs.size() != call.vargs.size()) {
    call.addError() << "Call to macro has wrong number arguments. Expected: "
                    << macro.vargs.size() << " but got " << call.vargs.size();
    return std::nullopt;
  }

  StatementList stmt_list;

  for (size_t i = 0; i < call.vargs.size(); i++) {
    if (auto *cvar = call.vargs.at(i).as<Variable>()) {
      if (auto *mvar = macro.vargs.at(i).as<Variable>()) {
        vars_[mvar->ident] = cvar->ident;
      } else {
        call.addError()
            << "Mismatched arg to macro call. Macro expects a map for arg "
            << macro.vargs.at(i).as<Map>()->ident << " but got a variable.";
      }
    } else if (auto *cmap = call.vargs.at(i).as<Map>()) {
      if (auto *mmap = macro.vargs.at(i).as<Map>()) {
        maps_[mmap->ident] = cmap->ident;
      } else {
        call.addError()
            << "Mismatched arg to macro call. Macro expects a variable for arg "
            << macro.vargs.at(i).as<Variable>()->ident << " but got a map.";
      }
    } else {
      if (auto *mvar = macro.vargs.at(i).as<Variable>()) {
        stmt_list.emplace_back(ast_.make_node<AssignVarStatement>(
            ast_.make_node<Variable>(get_new_var_ident(mvar->ident),
                                     Location(call.loc)),
            clone(ast_, call.vargs.at(i), call.vargs.at(i).loc()),
            Location(call.loc)));
        // As per the name these arg variables are not expecting to be mutated
        // because the caller passed in an expression instead of another
        // variable e.g.
        // macro add1($x) { $x += 1; $x } begin { add1(1 + 1);
        arg_vars_no_mutation_[mvar->ident] = &call;
        temp_vars_.insert(stmt_list.back().as<AssignVarStatement>()->var());
      } else if (auto *mmap = macro.vargs.at(i).as<Map>()) {
        call.addError()
            << "Mismatched arg to macro call. Macro expects a map for arg "
            << mmap->ident << " but got an expression.";
      }
    }
  }

  return make_block_expr(macro, stmt_list, call.loc);
}

std::optional<BlockExpr *> MacroExpander::expand(Macro &macro,
                                                 Identifier &ident)
{
  if (!macro.vargs.empty()) {
    ident.addError() << "Call to macro has no number arguments. Expected: "
                     << macro.vargs.size();
    return std::nullopt;
  }

  StatementList stmt_list;
  return make_block_expr(macro, stmt_list, ident.loc);
}

Pass CreateMacroExpansionPass()
{
  auto fn = [](ASTContext &ast) {
    auto macros = collect_macros(ast);
    if (ast.diagnostics().ok()) {
      MacroExpander expander(ast, "none", macros, {});
      expander.visit(ast.root);
    }
  };

  return Pass::create("MacroExpansion", fn);
}

} // namespace bpftrace::ast
