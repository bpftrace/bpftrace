#pragma once

#include "ast/passes/types/type_resolver.h"

namespace bpftrace::ast {

class ASTContext;

void RunTypeApplicator(ASTContext &ast, const ResolvedTypes &resolved_types);

} // namespace bpftrace::ast
