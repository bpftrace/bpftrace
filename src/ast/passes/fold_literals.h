#pragma once

#include "ast/ast.h"
#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Folds only a single expression.
//
// This may be used by subsequent passes when expressions are replaced by
// literals. Note however, that it is up to the pass to ensure that the full
// expression is recursively folded.
void fold(ASTContext &ast, Expression &expr);
// Re-visit the whole ast and re-fold
void fold(ASTContext &ast);

// Fold all nodes.
Pass CreateFoldLiteralsPass();

} // namespace bpftrace::ast
