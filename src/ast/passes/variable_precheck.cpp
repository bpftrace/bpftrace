#include "ast/passes/variable_precheck.h"

#include <variant>

#include "ast/ast.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

using VarOrigin = std::
    variant<VarDeclStatement *, AssignVarStatement *, SubprogArg *, Variable *>;

struct VarInfo {
  VarOrigin origin;
  bool was_assigned;
};

using Scope = Node *;

void add_origin_context(Diagnostic &d, const VarOrigin &origin)
{
  std::visit(
      [&d](auto &&arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, VarDeclStatement *>) {
          d.addContext(arg->loc) << "This is the initial declaration.";
        } else if constexpr (std::is_same_v<T, AssignVarStatement *>) {
          d.addContext(arg->loc) << "This is the initial assignment.";
        } else if constexpr (std::is_same_v<T, SubprogArg *>) {
          d.addContext(arg->loc) << "This is the function parameter.";
        } else if constexpr (std::is_same_v<T, Variable *>) {
          d.addContext(arg->loc) << "This is the loop variable.";
        }
      },
      origin);
}

class VariablePreCheck : public Visitor<VariablePreCheck> {
public:
  using Visitor<VariablePreCheck>::visit;

  void visit(Variable &var);
  void visit(VariableAddr &var_addr);
  void visit(VarDeclStatement &decl);
  void visit(AssignVarStatement &assignment);
  void visit(SubprogArg &arg);
  void visit(BlockExpr &block);
  void visit(For &f);
  void visit(Subprog &subprog);
  void visit(Probe &probe);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(Typeof &typeof_);
  void visit(Typeinfo &typeinfo);

private:
  VarInfo *find_variable(const std::string &name);
  void check_variable_decls();
  std::vector<Scope> scope_stack_;
  std::map<Scope, std::map<std::string, VarInfo>> variables_;
  uint32_t meta_depth_ = 0; // sizeof, offsetof, typeof, typeinfo
};

VarInfo *VariablePreCheck::find_variable(const std::string &name)
{
  for (auto *scope : scope_stack_) {
    if (auto scope_it = variables_.find(scope); scope_it != variables_.end()) {
      if (auto var_it = scope_it->second.find(name);
          var_it != scope_it->second.end()) {
        return &var_it->second;
      }
    }
  }
  return nullptr;
}

void VariablePreCheck::check_variable_decls()
{
  for (const auto &[scope, var_map] : variables_) {
    for (const auto &[ident, info] : var_map) {
      if (info.was_assigned) {
        continue;
      }
      if (const auto *decl = std::get_if<VarDeclStatement *>(&info.origin)) {
        (*decl)->addWarning()
            << "Variable " << ident << " was never assigned to.";
      }
    }
  }
}

void VariablePreCheck::visit(Variable &var)
{
  if (auto *info = find_variable(var.ident)) {
    if (!info->was_assigned && meta_depth_ == 0) {
      var.addWarning() << "Variable used before it was assigned: " << var.ident;
    }
  } else {
    var.addError() << "Undefined or undeclared variable: " << var.ident;
  }
}

void VariablePreCheck::visit(VariableAddr &var_addr)
{
  if (auto *found = find_variable(var_addr.var->ident)) {
    // We can't know if the pointer to a scratch variable was passed
    // to an external function for assignment so just mark it as assigned.
    found->was_assigned = true;
  } else {
    var_addr.var->addError()
        << "Undefined or undeclared variable: " << var_addr.var->ident;
  }
}

void VariablePreCheck::visit(VarDeclStatement &decl)
{
  // Only visit typeof, not the variable being declared
  visit(decl.typeof);

  const std::string &var_ident = decl.var->ident;

  if (const auto *info = find_variable(var_ident)) {
    auto &err = decl.addError();
    err << "Variable " << var_ident
        << " was already declared. Variable shadowing is not "
           "allowed.";
    add_origin_context(err, info->origin);
    return;
  }

  // Declaration without assignment - was_assigned = false
  if (!scope_stack_.empty()) {
    variables_[scope_stack_.back()][var_ident] = VarInfo{
      .origin = &decl, .was_assigned = false
    };
  }
}

void VariablePreCheck::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);

  if (std::holds_alternative<VarDeclStatement *>(assignment.var_decl)) {
    visit(assignment.var_decl);
  }

  const std::string &var_ident = assignment.var()->ident;
  if (auto *info = find_variable(var_ident)) {
    info->was_assigned = true;
  } else if (!scope_stack_.empty()) {
    variables_[scope_stack_.back()][var_ident] = VarInfo{
      .origin = &assignment, .was_assigned = true
    };
  }
}

void VariablePreCheck::visit(SubprogArg &arg)
{
  // Only visit typeof, not the variable being defined as a parameter
  visit(arg.typeof);
}

void VariablePreCheck::visit(BlockExpr &block)
{
  scope_stack_.push_back(&block);
  Visitor<VariablePreCheck>::visit(block);
  scope_stack_.pop_back();
}

void VariablePreCheck::visit(For &f)
{
  const auto &decl_name = f.decl->ident;
  if (const auto *info = find_variable(decl_name)) {
    auto &err = f.decl->addError();
    err << "Loop declaration shadows existing variable: " + decl_name;
    add_origin_context(err, info->origin);
  }

  visit(f.iterable);

  scope_stack_.push_back(&f);
  // Loop variable is always assigned
  variables_[&f][decl_name] = VarInfo{ .origin = f.decl, .was_assigned = true };

  visit(f.block);

  scope_stack_.pop_back();
}

void VariablePreCheck::visit(Subprog &subprog)
{
  scope_stack_.push_back(&subprog);

  // Function parameters are always assigned
  for (auto *arg : subprog.args) {
    variables_[&subprog][arg->var->ident] = VarInfo{ .origin = arg,
                                                     .was_assigned = true };
  }
  visit(subprog.args);
  visit(subprog.block);
  visit(subprog.return_type);

  check_variable_decls();
  scope_stack_.pop_back();
}

void VariablePreCheck::visit(Probe &probe)
{
  scope_stack_.push_back(&probe);
  Visitor<VariablePreCheck>::visit(probe);
  check_variable_decls();
  scope_stack_.pop_back();
}

void VariablePreCheck::visit(Sizeof &szof)
{
  meta_depth_++;
  Visitor<VariablePreCheck>::visit(szof);
  meta_depth_--;
}

void VariablePreCheck::visit(Offsetof &offof)
{
  meta_depth_++;
  Visitor<VariablePreCheck>::visit(offof);
  meta_depth_--;
}

void VariablePreCheck::visit(Typeof &typeof_)
{
  meta_depth_++;
  Visitor<VariablePreCheck>::visit(typeof_);
  meta_depth_--;
}

void VariablePreCheck::visit(Typeinfo &typeinfo)
{
  meta_depth_++;
  Visitor<VariablePreCheck>::visit(typeinfo);
  meta_depth_--;
}

} // namespace

Pass CreateVariablePreCheckPass()
{
  auto fn = [](ASTContext &ast) {
    // Variable state is effectively reset for each probe and subprog
    for (auto &subprog : ast.root->functions) {
      VariablePreCheck().visit(subprog);
    }
    for (auto &probe : ast.root->probes) {
      VariablePreCheck().visit(probe);
    }
  };

  return Pass::create("VariablePreCheck", fn);
}

} // namespace bpftrace::ast
