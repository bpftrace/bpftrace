#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/macro_expansion.h"
#include "ast/visitor.h"
#include "log.h"

namespace bpftrace::ast {

char MacroLookupError::ID;
void MacroLookupError::log(llvm::raw_ostream &OS) const
{
  // This is the default message, but most calls will handle this error and
  // apply to the relevant nodes directly.
  OS << "Unable to find macro " << name_;
}

static bool validate(Macro *macro)
{
  std::unordered_set<std::string> seen_mvars;
  std::unordered_set<std::string> seen_mmaps;
  for (const auto &arg : macro->vargs) {
    if (auto *mvar = arg.as<Variable>()) {
      auto inserted = seen_mvars.insert(mvar->ident);
      if (!inserted.second) {
        mvar->addError()
            << "Variable for macro argument has already been used: "
            << mvar->ident;
        return false;
      }
    } else if (auto *mmap = arg.as<Map>()) {
      auto inserted = seen_mmaps.insert(mmap->ident);
      if (!inserted.second) {
        mmap->addError() << "Map for macro argument has already been used: "
                         << mmap->ident;
        return false;
      }
    }
  }
  return true;
}

MacroRegistry MacroRegistry::create(ASTContext &ast)
{
  MacroRegistry registry;
  for (Macro *macro : ast.root->macros) {
    // Note that it is possible to define conflicting macros in this way. For
    // example, we could have:
    //
    //   macro foo($x, $y) {}
    //   macro foo(x, y) {}
    //
    // However we explicitly allow this, as long as they are added in such a way
    // that they will match with the most precise macros first. The newest macro
    // definition must not match with any existing macro definition.
    auto exists = registry.lookup(macro->name, macro->vargs);
    if (exists) {
      auto &err = macro->addError();
      err << "Redefinition of macro: " << macro->name;
      err.addContext((*exists)->loc) << "This is the original definition.";
      continue; // Skip this macro.
    }
    consumeError(std::move(exists));
    if (!validate(macro)) {
      continue;
    }
    // Add to the list matching this name.
    registry.macros_[macro->name].emplace_back(macro);
  }
  return registry;
}

static size_t distance(const Macro *macro, const std::vector<Expression> &args)
{
  // Any missing arguments either way are wrong; these dominate the other
  // differences by far, so we ensure that these are the least close macros.
  // This is why 1024 is used: we should never have a macro with this many
  // arguments, and we score 1 badness per incorrect argument.
  size_t d = 1024 * static_cast<size_t>(
                        std::abs(static_cast<long>(macro->vargs.size()) -
                                 static_cast<long>(args.size())));
  for (size_t i = 0; i < macro->vargs.size() && i < args.size(); i++) {
    if ((macro->vargs[i].is<Map>() && !args[i].is<Map>()) ||
        (macro->vargs[i].is<Variable>() && !args[i].is<Variable>())) {
      d++; // Incompatible arguments.
    }
  }
  return d;
}

Result<const Macro *> MacroRegistry::lookup(
    const std::string &name,
    const std::vector<Expression> &args) const
{
  const auto it = macros_.find(name);
  if (it == macros_.end()) {
    return make_error<MacroLookupError>(
        name,
        std::vector<const Macro *>()); // Nothing
                                       // with
                                       // this
                                       // name.
  }
  size_t min_distance = std::numeric_limits<size_t>::max();
  std::vector<const Macro *> closest;
  for (const auto *m : it->second) {
    size_t d = distance(m, args);
    if (d == 0) {
      return m; // Matched.
    }
    if (d < min_distance) {
      min_distance = d;
      closest.clear();
    }
    if (d == min_distance) {
      closest.push_back(m);
    }
  }
  return make_error<MacroLookupError>(name, std::move(closest));
}

class MacroExpander : public Visitor<MacroExpander> {
public:
  MacroExpander(ASTContext &ast,
                const MacroRegistry &registry,
                std::vector<const Macro *> &stack,
                bool should_rename = true)
      : ast_(ast),
        registry_(registry),
        stack_(stack),
        should_rename_(should_rename) {};

  using Visitor<MacroExpander>::visit;

  void visit(AssignVarStatement &assignment);
  void visit(Variable &var);
  void visit(VarDeclStatement &decl);
  void visit(Map &map);
  void visit(Expression &expr);

  std::optional<BlockExpr *> expand(const Macro &macro, Call &call);
  std::optional<BlockExpr *> expand(const Macro &macro, Identifier &ident);

private:
  ASTContext &ast_;
  const MacroRegistry &registry_;
  std::vector<const Macro *> stack_;
  bool should_rename_;

  bool rename_ok();
  std::string get_new_var_ident(std::string original_ident);

  // Maps of macro map/var names -> callsite map/var names
  std::unordered_map<std::string, std::string> maps_;
  std::unordered_map<std::string, std::string> vars_;
  std::unordered_set<std::string> renamed_vars_;
  std::unordered_map<std::string, Expression> passed_exprs_;
};

void MacroExpander::visit(AssignVarStatement &assignment)
{
  if (!rename_ok()) {
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
  if (!rename_ok()) {
    return;
  }

  auto *var = decl.var;
  if (vars_.contains(var->ident)) {
    decl.addError() << "Variable declaration shadows macro arg " << var->ident;
    return;
  }
  renamed_vars_.insert(var->ident);

  visit(decl.typeof);
  visit(decl.var);
}

void MacroExpander::visit(Variable &var)
{
  if (!rename_ok()) {
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
  if (!rename_ok()) {
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
      expr = clone(ast_, ident->loc, it->second);
      // Create a new expander because we're visiting an expression passed into
      // the macro so it's not part of the surounding macro code and therefore
      // variables, maps, and idents in this expression shouldn't be modified
      // and this expression *is* permitted to be un-hygienic.

      MacroExpander expander(ast_, registry_, stack_, false);
      expander.visit(expr);
      return;
    }
  }
  if (call) {
    visit(call->vargs);
  }

  std::vector<Expression> empty;
  const std::string &name = ident ? ident->ident : call->func;
  const std::vector<Expression> &args = ident ? empty : call->vargs;

  auto result = registry_.lookup(name, args);
  if (!result) {
    auto done = handleErrors(
        std::move(result), [&](const MacroLookupError &lookupErr) {
          const auto &closest = lookupErr.closest();
          if (closest.empty()) {
            // It does not match any macros. This is not really an error, and
            // just means that we don't process or expand this instance.
            return;
          }
          const auto *macro = closest[0];
          auto &err = ident ? ident->addError() : call->addError();
          err << "Call to " << name << "() "
              << "has arguments that do not match any definition.";

          // We can't say exactly what they intended here, so we break this into
          // a suitable hint, pointing to the closest macro we could find.
          if (macro->vargs.size() != args.size()) {
            err.addContext(macro->loc)
                << "The closest definition of " << macro->name
                << "() has a different number of arguments. "
                << "Expected: " << macro->vargs.size() << " but got "
                << args.size();
            return;
          }

          // Break down the mismatched arguments.
          for (size_t i = 0; i < macro->vargs.size() && i < args.size(); i++) {
            if (auto *mmap = macro->vargs.at(i).as<Map>()) {
              if (args.at(i).is<Variable>()) {
                auto &arg_err = args[i].node().addError();
                arg_err << "Mismatched arg. " << macro->name
                        << "() expects a map for arg " << mmap->ident
                        << " but got a variable.";
                arg_err.addContext(mmap->loc)
                    << "This is the argument in the closest definition.";
              } else {
                auto &arg_err = args[i].node().addError();
                arg_err << "Mismatched arg. " << macro->name
                        << "() expects a map for arg " << mmap->ident
                        << " but got an expression.";
                arg_err.addContext(mmap->loc)
                    << "This is the argument in the closest definition.";
              }
            } else if (auto *mvar = macro->vargs.at(i).as<Variable>()) {
              if (args.at(i).is<Map>()) {
                auto &arg_err = args[i].node().addError();
                arg_err << "Mismatched arg. " << macro->name
                        << "() expects a variable for arg " << mvar->ident
                        << " but got a map.";
                arg_err.addContext(mvar->loc)
                    << "This is the argument in the closest definition.";
              } else {
                auto &arg_err = args[i].node().addError();
                arg_err << "Mismatched arg. " << macro->name
                        << "() expects a variable for arg " << mvar->ident
                        << " but got an expression.";
                arg_err.addContext(mvar->loc)
                    << "This is the argument in the closest definition.";
              }
            }
          }
        });
    if (!done) {
      // This should not happen; add the error.
      LOG(BUG) << done.takeError();
    }
    return;
  }

  const auto *macro = *result;
  for (size_t i = 0; i < stack_.size(); ++i) {
    // We cannot expand recursively at this time, however this may happen
    // later using apply. We provide this helpful error.
    if (stack_.at(i) == macro) {
      auto &err = expr.node().addError();
      err << "Recursive macro call detected. Call chain: ";
      for (size_t j = i; j < stack_.size(); ++j) {
        err << stack_.at(j)->name << " > ";
      }
      err << macro->name;
      return;
    }
  }

  // Expand this macro.
  stack_.push_back(macro);
  auto r = ident ? MacroExpander(ast_, registry_, stack_).expand(*macro, *ident)
                 : MacroExpander(ast_, registry_, stack_).expand(*macro, *call);
  stack_.pop_back();
  if (r) {
    expr.value = *r;
  }
}

bool MacroExpander::rename_ok()
{
  return !stack_.empty() && should_rename_;
}

std::string MacroExpander::get_new_var_ident(std::string original_ident)
{
  // This is a name like $$foo_0_x, where `x` is the original name,
  // `foo` is the macro name, and `0` is the depth of the call.
  assert(rename_ok());
  const auto *macro = stack_.back();
  std::string base = "$$" + macro->name;
  if (stack_.size() != 1) {
    base += "_" + std::to_string(stack_.size());
  }
  return base + "_" + original_ident;
}

std::optional<BlockExpr *> MacroExpander::expand(const Macro &macro, Call &call)
{
  if (macro.vargs.size() != call.vargs.size()) {
    return std::nullopt;
  }

  StatementList stmt_list;
  for (size_t i = 0; i < macro.vargs.size(); i++) {
    if (auto *mident = macro.vargs.at(i).as<Identifier>()) {
      if (call.vargs.at(i).is<Variable>() || call.vargs.at(i).is<Map>()) {
        // Wrap variables and maps in a block to avoid mutation.
        passed_exprs_[mident->ident] = ast_.make_node<BlockExpr>(
            call.loc, StatementList({}), call.vargs.at(i));
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

  auto *cloned_block = clone(ast_, call.loc, macro.block);
  visit(cloned_block);
  return cloned_block;
}

std::optional<BlockExpr *> MacroExpander::expand(const Macro &macro,
                                                 Identifier &ident)
{
  if (!macro.vargs.empty()) {
    ident.addError() << "Call to " << macro.name
                     << "() has the wrong number of arguments. Expected: "
                     << macro.vargs.size() << " but got 0.";
    return std::nullopt;
  }

  auto *cloned_block = clone(ast_, ident.loc, macro.block);
  visit(cloned_block);
  return cloned_block;
}

void expand_macro(ASTContext &ast,
                  Expression &expr,
                  const MacroRegistry &registry)
{
  std::vector<const Macro *> stack;
  MacroExpander expander(ast, registry, stack);
  expander.visit(expr);
}

Pass CreateMacroExpansionPass()
{
  auto fn = [](ASTContext &ast) -> MacroRegistry {
    auto macros = MacroRegistry::create(ast);
    std::vector<const Macro *> stack;
    MacroExpander expander(ast, macros, stack);
    expander.visit(ast.root);
    return macros;
  };

  return Pass::create("MacroExpansion", fn);
}

} // namespace bpftrace::ast
