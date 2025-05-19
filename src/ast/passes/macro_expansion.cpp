#include <format>
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

  std::optional<Block *> expand(Macro &macro, Call &call);
  bool check_recursive_call(const std::string &macro_name, const Call &call);

private:
  ASTContext &ast_;
  const std::string macro_name_;
  const std::unordered_map<std::string, Macro *> &macros_;

  std::string get_new_var_ident(std::string original_ident);

  // Maps of macro map/var names -> callsite map/var names
  std::unordered_map<std::string, std::string> maps_;
  std::unordered_map<std::string, std::string> vars_;
  std::unordered_set<Variable *> temp_vars_;
  std::unordered_map<std::string, Call *> arg_vars_no_mutation_;
  const std::vector<std::string> macro_stack_;
};

class MacroCollection : public Visitor<MacroCollection> {
public:
  MacroCollection(ASTContext &ast, BPFtrace &b);
  void collect_macros();

  using Visitor<MacroCollection>::visit;

  void visit(Expression &expr);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  std::unordered_map<std::string, Macro *> macros_;
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
  assert(!macro_stack_.empty());
}

void MacroExpander::visit(AssignVarStatement &assignment)
{
  auto *var = assignment.var();
  if (temp_vars_.contains(var)) {
    // Don't change variable names if this is a variable assignment
    // that we created to represent the passed in expression e.g.
    // macro add_one($x) { $x + 1 } BEGIN { $a = 1; print(add_one($a + 1)); }
    // will become
    // BEGIN { $a = 1; print({let $$add_one_$a = $a + 1; $$add_one_$a + 1}); }
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
  if (auto it = vars_.find(var.ident); it != vars_.end()) {
    var.ident = it->second;
  } else if (!temp_vars_.contains(&var)) {
    var.ident = get_new_var_ident(var.ident);
  }
}

void MacroExpander::visit(Map &map)
{
  if (auto it = maps_.find(map.ident); it != maps_.end()) {
    map.ident = it->second;
  } else {
    map.addError() << "Unhygienic access to map: " << map.ident
                   << ". Maps must be passed into the macro as arguments.";
  }
}

bool MacroExpander::check_recursive_call(const std::string &macro_name,
                                         const Call &call)
{
  for (size_t i = 0; i < macro_stack_.size(); ++i) {
    if (macro_stack_.at(i) == macro_name) {
      auto &err = call.addError();
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
  auto *call = expr.as<Call>();
  if (!call) {
    // Recursively expand the new expression, which may again contain macros...
    Visitor<MacroExpander>::visit(expr);
    return;
  }

  for (auto &varg : call->vargs) {
    visit(varg);
  }

  if (auto it = macros_.find(call->func); it != macros_.end()) {
    Macro *macro = it->second;

    if (check_recursive_call(macro->name, *call)) {
      return;
    }

    auto next_macro_stack = macro_stack_;
    next_macro_stack.push_back(macro->name);

    auto r = MacroExpander(
                 ast_, macro->name, macros_, std::move(next_macro_stack))
                 .expand(*macro, *call);
    if (r) {
      expr.value = *r;
    }
  }
}

std::string MacroExpander::get_new_var_ident(std::string original_ident)
{
  return std::format("$${}_{}", macro_name_, original_ident);
}

std::optional<Block *> MacroExpander::expand(Macro &macro, Call &call)
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
        // macro add1($x) { $x += 1; $x } BEGIN { add1(1 + 1);
        arg_vars_no_mutation_[mvar->ident] = &call;
        temp_vars_.insert(stmt_list.back().as<AssignVarStatement>()->var());
      } else if (auto *mmap = macro.vargs.at(i).as<Map>()) {
        call.addError()
            << "Mismatched arg to macro call. Macro expects a map for arg "
            << mmap->ident << " but got an expression.";
      }
    }
  }

  for (auto expr : macro.block->stmts) {
    stmt_list.push_back(clone(ast_, expr, call.loc));
  }

  auto *cloned_block =
      macro.block->expr.has_value()
          ? ast_.make_node<Block>(std::move(stmt_list),
                                  clone(ast_, *macro.block->expr, call.loc),
                                  Location(macro.loc))
          : ast_.make_node<Block>(std::move(stmt_list), Location(call.loc));

  visit(cloned_block);

  if (ast_.diagnostics().ok()) {
    return cloned_block;
  }

  return std::nullopt;
}

MacroCollection::MacroCollection(ASTContext &ast, BPFtrace &b)
    : ast_(ast), bpftrace_(b)
{
}

// This is similar to MacroExpander::visit(Expression &expr) but doesn't have
// to check for macro recursion because we're at the top level of the AST
// and avoids the need to keep some state in MacroExpander indicating if we're
// at the top level of the AST (e.g. where we don't want to rename variables)
void MacroCollection::visit(Expression &expr)
{
  auto *call = expr.as<Call>();
  if (!call) {
    Visitor<MacroCollection>::visit(expr);
    return;
  }

  for (auto &varg : call->vargs) {
    visit(varg);
  }

  if (auto it = macros_.find(call->func); it != macros_.end()) {
    Macro *macro = it->second;
    auto r = MacroExpander(ast_, macro->name, macros_, { macro->name })
                 .expand(*macro, *call);
    if (r) {
      expr.value = *r;
    }
  }
}

void MacroCollection::collect_macros()
{
  for (Macro *macro : ast_.root->macros) {
    if (macros_.contains(macro->name)) {
      macro->addError() << "Redifinition of macro: " << macro->name;
      return;
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
          return;
        }
      } else if (auto *mmap = arg.as<Map>()) {
        auto inserted = seen_mmaps.insert(mmap->ident);
        if (!inserted.second) {
          mmap->addError() << "Map for macro argument has already been used: "
                           << mmap->ident;
          return;
        }
      }
    }

    macros_[macro->name] = macro;
  }
}

Pass CreateMacroExpansionPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    MacroCollection collector(ast, b);
    collector.collect_macros();
    if (ast.diagnostics().ok()) {
      collector.visit(ast.root);
    }
  };

  return Pass::create("MacroExpansion", fn);
}

} // namespace bpftrace::ast
