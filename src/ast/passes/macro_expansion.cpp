#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/macro_expansion.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

MacroRegistry MacroRegistry::create(ASTContext &ast)
{
  MacroRegistry registry;
  for (Macro *macro : ast.root->macros) {
    // Note that it is possible to define conflicting macros in this way. For
    // example, we could have:
    //
    //   macro foo($x, $y) {}
    //   macro foo(...) {}
    //
    // However we explicitly allow this, as long as they are added in such a way
    // that they will match with the most precise macros first. The newest macro
    // definition must not match with any existing macro definition.
    auto *existing = registry.lookup(macro->name, macro->vargs);
    if (existing != nullptr) {
      auto &err = macro->addError();
      err << "Redefinition of existing macro.";
      err.addContext(existing->loc) << "This is the original definition.";
      continue; // Skip this macro.
    }
    // Add to the list matching this name.
    registry.macros_[macro->name].emplace_back(macro);
  }
  return registry;
}

static bool matches(const Macro *macro, const std::vector<Expression> &args)
{
  if (args.size() < macro->vargs.size()) {
    return false; // Insufficient arguments.
  }
  for (size_t i = 0; i < macro->vargs.size() && i < args.size(); i++) {
    if ((macro->vargs[i].is<Map>() && !args[i].is<Map>()) ||
        (macro->vargs[i].is<Variable>() && !args[i].is<Variable>())) {
      return false; // Incompatible arguments.
    }
  }
  if (args.size() > macro->vargs.size()) {
    return macro->varargs; // Only okay if varargs is true.
  }
  return true; // It matches.
}

const Macro *MacroRegistry::lookup(const std::string &name,
                                   const std::vector<Expression> &args) const
{
  const auto it = macros_.find(name);
  if (it == macros_.end()) {
    return nullptr; // Nothing with this name.
  }
  for (const auto *m : it->second) {
    if (matches(m, args)) {
      return m;
    }
  }
  return nullptr; // Nothing matching.
}

const Macro *MacroRegistry::lookup(const std::string &name) const
{
  const auto it = macros_.find(name);
  if (it != macros_.end()) {
    return it->second.front();
  }
  return nullptr; // Nothing.
}

class MacroExpander : public Visitor<MacroExpander> {
public:
  MacroExpander(ASTContext &ast,
                const MacroRegistry &registry,
                std::vector<const Macro *> &stack,
                int depth = 0)
      : ast_(ast), registry_(registry), stack_(stack), depth_(depth) {};

  using Visitor<MacroExpander>::visit;

  void visit(AssignVarStatement &assignment);
  void visit(Variable &var);
  void visit(VarDeclStatement &decl);
  void visit(Map &map);
  void visit(Expression &expr);

  std::optional<BlockExpr *> expand(const Macro &macro, Call &call);
  std::optional<BlockExpr *> expand(const Macro &macro, Identifier &ident);

  int expanded() const
  {
    return done_;
  }

private:
  ASTContext &ast_;
  const MacroRegistry &registry_;
  std::vector<const Macro *> stack_;
  const int depth_;
  int done_ = 0; // Number completed.

  bool is_top_level();
  std::string get_new_var_ident(std::string original_ident);

  // Maps of macro map/var names -> callsite map/var names
  std::unordered_map<std::string, std::string> maps_;
  std::unordered_map<std::string, std::string> vars_;
  std::unordered_set<std::string> renamed_vars_;
  std::unordered_map<std::string, Expression> passed_exprs_;
};

void MacroExpander::visit(AssignVarStatement &assignment)
{
  if (is_top_level()) {
    visit(assignment.expr);
    return;
  }

  auto *var = assignment.var();

  // Don't rename any variable passed by reference.
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
  auto *var = decl.var;
  if (vars_.contains(var->ident)) {
    decl.addError() << "Variable declaration shadows macro arg " << var->ident;
    return;
  }
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

void MacroExpander::visit(Expression &expr)
{
  auto *ident = expr.as<Identifier>();
  auto *call = expr.as<Call>();

  if (!ident && !call) {
    Visitor<MacroExpander>::visit(expr);
    return;
  }

  if (ident) {
    if (auto it = passed_exprs_.find(ident->ident); it != passed_exprs_.end()) {
      expr = clone(ast_, it->second, ident->loc);
      // Create a new expander because we're visiting an expression passed into
      // the macro so it's not part of the surounding macro code and therefore
      // variables, maps, and idents in this expression shouldn't be modified.
      //
      // We temporarily remove our current macro from the back of the stack,
      // because this expression *is* permitted to be non-hermetic.
      auto *last = stack_.back();
      stack_.pop_back();
      MacroExpander expander(ast_, registry_, stack_, depth_);
      expander.visit(expr);
      stack_.push_back(last);
      return;
    }
  }
  if (call) {
    visit(call->vargs);
  }

  std::vector<Expression> empty;
  const std::string &name = ident ? ident->ident : call->func;
  const std::vector<Expression> &args = ident ? empty : call->vargs;

  const auto *macro = registry_.lookup(name, args);
  if (macro == nullptr) {
    // This is not a matching macro. Are there any? If there are, treat this as
    // an error and add the extra context so the user sees it.
    const auto *other = registry_.lookup(name);
    if (other != nullptr) {
      auto &err = expr.node().addError();
      err << "Partially matching macro " << name << ".";
      err.addContext(other->loc) << "Did you mean this one?";
    }
    return;
  }
  for (size_t i = 0; i < stack_.size(); ++i) {
    // We cannot expand recursively at this time, however this may happen
    // later using apply. We provide this helpful error.
    if (stack_.at(i) == macro) {
      auto &err = expr.node().addError();
      err << "Recursive macro call detected. Call chain: ";
      for (; i < stack_.size(); ++i) {
        err << stack_.at(i)->name << " > ";
      }
      err << macro->name;
      err.addHint() << "If you're sneaky, you can use `apply`.";
      return;
    }
  }

  // Expand this macro.
  stack_.push_back(macro);
  auto r = ident ? MacroExpander(ast_, registry_, stack_, depth_)
                       .expand(*macro, *ident)
                 : MacroExpander(ast_, registry_, stack_, depth_)
                       .expand(*macro, *call);
  stack_.pop_back();
  if (r) {
    expr.value = *r;
    done_++;
  }
}

bool MacroExpander::is_top_level()
{
  return stack_.empty();
}

std::string MacroExpander::get_new_var_ident(std::string original_ident)
{
  // This is a name like $$foo_0_x, where `x` is the original name,
  // `foo` is the macro name, and `0` is the depth of the call.
  assert(!is_top_level());
  const auto *macro = stack_.back();
  return std::string("$$") + macro->name + std::string("_") +
         std::to_string(depth_) + "_" + original_ident;
}

std::optional<BlockExpr *> MacroExpander::expand(const Macro &macro, Call &call)
{
  // This will only match if the arguments are correct. If the macro accepts
  // varargs, then we need to wrap the final arguments into a tuple
  // expression.
  //
  // Note that this may be an empty tuple which is passed to the macro also.
  if (macro.varargs != nullptr) {
    std::vector<Expression> tuple;
    while (call.vargs.size() > macro.vargs.size()) {
      tuple.push_back(call.vargs.back());
      call.vargs.pop_back();
    }
    std::reverse(tuple.begin(), tuple.end());
    passed_exprs_[macro.varargs->ident] = ast_.make_node<Tuple>(
        std::move(tuple), Location(call.loc));
  }

  StatementList stmt_list;
  for (size_t i = 0; i < macro.vargs.size(); i++) {
    if (auto *mident = macro.vargs.at(i).as<Identifier>()) {
      if (call.vargs.at(i).is<Variable>() || call.vargs.at(i).is<Map>()) {
        // Wrap variables and maps in a block to avoid mutation.
        passed_exprs_[mident->ident] = ast_.make_node<BlockExpr>(
            StatementList({}), call.vargs.at(i), Location(call.loc));
      } else {
        passed_exprs_[mident->ident] = call.vargs.at(i);
      }
    } else if (auto *mvar = macro.vargs.at(i).as<Variable>()) {
      auto *cvar = call.vargs.at(i).as<Variable>();
      assert(cvar != nullptr); // Required by lookup.
      vars_[mvar->ident] = cvar->ident;
    } else if (auto *mmap = macro.vargs.at(i).as<Map>()) {
      auto *cmap = call.vargs.at(i).as<Map>();
      assert(cmap != nullptr); // Required by lookup.
      maps_[mmap->ident] = cmap->ident;
    }
  }

  auto *cloned_block = clone(ast_, macro.block, call.loc);
  visit(cloned_block);
  return cloned_block;
}

std::optional<BlockExpr *> MacroExpander::expand(const Macro &macro,
                                                 Identifier &ident)
{
  // It is possible that this is a vararg macro, in which case we must
  // construct the empty tuple type that is passed here.
  if (macro.varargs) {
    auto *mident = macro.vargs.back().as<Identifier>();
    assert(mident != nullptr);
    passed_exprs_[mident->ident] = ast_.make_node<Tuple>(ExpressionList({}),
                                                         Location(ident.loc));
  }

  auto *cloned_block = clone(ast_, macro.block, ident.loc);
  visit(cloned_block);
  return cloned_block;
}

bool expand(ASTContext &ast,
            MacroRegistry &registry,
            Expression &expr,
            int depth)
{
  std::vector<const Macro *> stack;
  MacroExpander expander(ast, registry, stack, depth);
  expander.visit(expr);
  return expander.expanded() > 0;
}

Pass CreateMacroExpansionPass()
{
  auto fn = [](ASTContext &ast) {
    auto macros = MacroRegistry::create(ast);
    std::vector<const Macro *> stack;
    MacroExpander expander(ast, macros, stack);
    expander.visit(ast.root);
    return macros;
  };

  return Pass::create("MacroExpansion", fn);
}

} // namespace bpftrace::ast
