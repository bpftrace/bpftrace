#pragma once

#include <string>
#include <vector>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/pass_manager.h"

namespace bpftrace::ast {

class MacroLookupError : public ErrorInfo<MacroLookupError> {
public:
  MacroLookupError(std::string name, std::vector<const Macro *> closest)
      : name_(std::move(name)), closest_(std::move(closest)) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

  const std::vector<const Macro *> &closest() const
  {
    return closest_;
  }

private:
  std::string name_;
  std::vector<const Macro *> closest_;
};

class MacroRegistry : public State<"macro-registry"> {
public:
  // Creates a new registry based on an AST.
  //
  // This may add errors to conflicting macros.
  static MacroRegistry create(ASTContext &ast);

  // Lookup a macro based on a name and set of arguments.
  //
  // If no matching macro is found, `nullptr` is returned.
  Result<const Macro *> lookup(const std::string &name,
                               const std::vector<Expression> &args) const;

private:
  // This holds the definitions for all discovered macros.
  std::map<std::string, std::vector<Macro *>> macros_;
};

// Expand a macro directly within an expression.
void expand_macro(ASTContext &ast, Expression &expr, const MacroRegistry &registry);

// Expand all possible macros. Macros can be defined recursively, and in these
// cases they are not expanded recursively. Instead, it is the responsibility
// of the caller to reject these late calls or call `expand` above (to a limit).
Pass CreateMacroExpansionPass();

} // namespace bpftrace::ast
