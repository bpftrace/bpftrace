#pragma once

#include "ast/passes/types/type_resolver.h"

namespace bpftrace::ast {

class MacroRegistry;

// Runs the AST transformer, returns true if any transforms were made.
bool RunAstTransformer(ASTContext &ast,
                       const MacroRegistry &macro_registry,
                       const ResolvedTypes &resolved_types);

} // namespace bpftrace::ast
