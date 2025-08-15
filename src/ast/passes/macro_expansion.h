#pragma once

#include <string>
#include <vector>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/pass_manager.h"

namespace bpftrace::ast {

class MacroRegistry : public State<"macro-registry"> {
public:
  // Creates a new registry based on an AST.
  //
  // This may add errors to conflicting macros.
  static MacroRegistry create(ASTContext &ast);

  // Lookup a macro based on a name and set of arguments.
  //
  // If no matching macro is found, `nullptr` is returned.
  const Macro *lookup(const std::string &name,
                      const std::vector<Expression> &args) const;

  // Lookup any matching macro based on the name.
  const Macro *lookup(const std::string &name) const;

private:
  // This holds the definitions for all discovered macros.
  std::map<std::string, std::vector<Macro *>> macros_;
};

// Potentially expand a macro expression. If expansion occurs `true` is
// returned. It is the responsibility of the caller to ensure that they do not
// recursive infinitely expanding recursive macros.
bool expand(ASTContext &ast,
            MacroRegistry &registry,
            Expression &expr,
            int depth);

// Expand all possible macros. Macros can be defined recursively, and in these
// cases they are not expanded recursively. Instead, it is the responsibility
// of the caller to reject these late calls or call `expand` above (to a limit).
Pass CreateMacroExpansionPass();

} // namespace bpftrace::ast
