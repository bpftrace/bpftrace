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
  std::unordered_set<std::string> seen_idents;
  std::unordered_set<std::string> seen_type_params;

  for (const auto &ident : macro->type_params) {
    auto inserted = seen_type_params.insert(ident->ident);
    if (!inserted.second) {
      ident->addError()
          << "Type param for macro argument has already been used: "
          << ident->ident;
      return false;
    }
  }

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
    } else if (auto *ident = arg.as<Identifier>()) {
      auto inserted = seen_idents.insert(ident->ident);
      if (!inserted.second) {
        ident->addError() << "Ident for macro argument has already been used: "
                          << ident->ident;
        return false;
      } else if (seen_type_params.contains(ident->ident)) {
        ident->addError() << "Ident for macro argument has already been used "
                             "as a type param: "
                          << ident->ident;
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
    auto exists = registry.lookup(
        macro->name, macro->vargs, macro->type_params.size(), macro->is_stdlib);
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

static size_t distance(const Macro *macro,
                       const std::vector<Expression> &args,
                       size_t num_types)
{
  // Any missing arguments either way are wrong; these dominate the other
  // differences by far, so we ensure that these are the least close macros.
  // This is why 1024 is used: we should never have a macro with this many
  // arguments, and we score 1 badness per incorrect argument.
  size_t d = 1024 * static_cast<size_t>(
                        std::abs(static_cast<long>(macro->vargs.size()) -
                                 static_cast<long>(args.size())));
  // A differing number of type parameters means a different macro signature,
  // so this dominates just like a differing number of arguments.
  d += 1024 * static_cast<size_t>(
                  std::abs(static_cast<long>(macro->type_params.size()) -
                           static_cast<long>(num_types)));
  for (size_t i = 0; i < macro->vargs.size() && i < args.size(); i++) {
    if ((macro->vargs[i].is<Map>() && !args[i].is<Map>()) ||
        (macro->vargs[i].is<Variable>() && !args[i].is<Variable>())) {
      d++; // Incompatible arguments.
    }
  }
  return d;
}

Result<const Macro *> MacroRegistry::lookup(const std::string &name,
                                            const std::vector<Expression> &args,
                                            size_t num_types,
                                            std::optional<bool> is_stdlib) const
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
  const Macro *exact_stdlib_match = nullptr;
  const Macro *exact_user_match = nullptr;
  for (const auto *m : it->second) {
    // When a lookup explicitly targets stdlib or user-defined macros, treat
    // the other class as invisible. This avoids turning unrelated builtin or
    // function calls into macro mismatch errors.
    if (is_stdlib && m->is_stdlib != *is_stdlib) {
      continue;
    }

    size_t d = distance(m, args, num_types);
    if (d == 0) {
      if (m->is_stdlib && !exact_stdlib_match) {
        exact_stdlib_match = m;
      } else if (!m->is_stdlib && !exact_user_match) {
        exact_user_match = m;
      }
    }
    if (d < min_distance) {
      min_distance = d;
      closest.clear();
    }
    if (d == min_distance) {
      closest.push_back(m);
    }
  }

  // When both user and stdlib definitions match, prefer the user-defined
  // macro. Filtered lookups only populate one of these pointers.
  if (exact_user_match) {
    return exact_user_match;
  }
  if (exact_stdlib_match) {
    return exact_stdlib_match;
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
  void visit(Sizeof &sizeof_node);
  void visit(Offsetof &offsetof_node);
  void visit(Typeof &typeof_node);

  void visit_expr_or_type(ExprOrType &record);
  void substitute_type_param(ParsedType *&type);

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
  std::unordered_map<std::string, ParsedType *> type_params_;
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

// Don't expand bare identifiers in type contexts (e.g. casts, sizeof,
// offsetof). A bare identifier here is intended as a type name, not a macro
// invocation. Use the call syntax (e.g. sizeof(mymacro())) or typeof wrapper
// (e.g. (typeof(mymacro()))x) to force macro expansion in type contexts.
void MacroExpander::visit_expr_or_type(ExprOrType &record)
{
  if (auto *expr = std::get_if<Expression>(&record)) {
    auto *ident = expr->as<Identifier>();
    if (ident) {
      if (auto it = type_params_.find(ident->ident); it != type_params_.end()) {
        record = clone(ast_, ident->loc, it->second);
        return;
      } else if (!passed_exprs_.contains(ident->ident)) {
        // Bare identifier that isn't a macro expression argument — treat it as
        // a type name rather than expanding it as a macro.
        return;
      }
    }
    visit(*expr);
  } else {
    auto *parsed_type = std::get<ParsedType *>(record);
    substitute_type_param(parsed_type);
    record = parsed_type;
  }
}

// Replace a type parameter referenced within `type` with the type argument it
// was bound to. The replacement happens at the innermost (leaf) type so that
// any pointer/array wrappers around the type parameter are preserved, e.g. a
// type param `b` bound to `uint64*` used as `b*` becomes `uint64**`.
void MacroExpander::substitute_type_param(ParsedType *&type)
{
  ParsedType *parsed_type = type;
  ParsedType *parent = nullptr;
  while (parsed_type->inner) {
    parent = parsed_type;
    parsed_type = parsed_type->inner;
  }
  auto it = type_params_.find(parsed_type->name);
  if (it == type_params_.end()) {
    return;
  }
  auto *type_param = it->second;
  assert(type_param != nullptr);

  switch (parsed_type->kind) {
    case ParsedType::Kind::Struct:
    case ParsedType::Kind::Union:
    case ParsedType::Kind::Enum: {
      // struct enum or struct struct is not supported syntax
      if (type_param->kind == ParsedType::Kind::Identifier) {
        parsed_type->name = type_param->name;
      } else {
        auto &error = parsed_type->addError();
        error << "Type arg '" << type_param->type_name()
              << "' is incompatible with how the type param is used in the "
                 "macro body.";
        if (!type_param->inner) {
          error.addHint() << "Try just passing the raw ident: '"
                          << type_param->name << "'";
        }
      }
      return;
    }
    case ParsedType::Kind::Identifier: {
      if (!parent) {
        type = clone(ast_, parsed_type->loc, type_param);
      } else {
        parent->inner = clone(ast_, parsed_type->loc, type_param);
      }
      return;
    }
    case ParsedType::Kind::Pointer:
    case ParsedType::Kind::Array: {
      LOG(BUG) << "ParsedType bottom can't be a pointer or array";
      break;
    }
  }
}

void MacroExpander::visit(Sizeof &sizeof_node)
{
  visit_expr_or_type(sizeof_node.record);
}

void MacroExpander::visit(Offsetof &offsetof_node)
{
  visit_expr_or_type(offsetof_node.record);
}

void MacroExpander::visit(Typeof &typeof_node)
{
  visit_expr_or_type(typeof_node.record);
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
    for (auto *&type : call->type_args) {
      substitute_type_param(type);
    }
  }

  std::vector<Expression> empty;
  const std::string &name = ident ? ident->ident : call->func;
  const std::vector<Expression> &args = ident ? empty : call->vargs;
  const size_t num_types = ident ? 0 : call->type_args.size();

  // If we're being called from a stdlib macro then only expand other stdlib
  // macros not user-defined macros that also happen to match
  std::optional<bool> restrict_to_stdlib = std::nullopt;
  if (!stack_.empty() && stack_.back()->is_stdlib) {
    restrict_to_stdlib = true;
  }
  auto result = registry_.lookup(name, args, num_types, restrict_to_stdlib);
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

          if (macro->type_params.size() != num_types) {
            err.addContext(macro->loc)
                << "The closest definition of " << macro->name
                << "() has a different number of type parameters. "
                << "Expected: " << macro->type_params.size() << " but got "
                << num_types;
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
  if (macro.vargs.size() != call.vargs.size() ||
      macro.type_params.size() != call.type_args.size()) {
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

  for (size_t i = 0; i < macro.type_params.size(); i++) {
    auto *mident = macro.type_params.at(i);
    assert(mident != nullptr); // Required by lookup.
    auto *type = call.type_args.at(i);
    assert(type != nullptr); // Required by lookup.
    type_params_[mident->ident] = type;
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

class TypeParamCheck : public Visitor<TypeParamCheck> {
public:
  explicit TypeParamCheck(ASTContext &ast) : ast_(ast) {};

  using Visitor<TypeParamCheck>::visit;
  void visit(Call &call);

private:
  ASTContext &ast_;
};

void TypeParamCheck::visit(Call &call)
{
  if (!call.type_args.empty()) {
    call.addError()
        << "Type args are not supported for function calls only macros";
  }
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

    TypeParamCheck type_param_check(ast);
    type_param_check.visit(ast.root);

    return macros;
  };

  return Pass::create("MacroExpansion", fn);
}

} // namespace bpftrace::ast
