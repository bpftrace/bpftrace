#pragma once

#include "ast/pass_manager.h"
#include "bpftrace.h"

namespace bpftrace::ast {

// No pass exists yet, this just gets called
// from inside semantic_analyser because this
// relies on previous and future type resolution
void simplify(ASTContext &ast, Expression &expr, BPFtrace &b);

} // namespace bpftrace::ast
