#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// ContextTypes is a sentinel value that indicates that the pass has run.
class ContextTypes : public State<"ContextTypes"> {};

// The context reoslution pass will remove all instances of `args` and `argN` from the AST,
// and replace with the use of the `ctx` builtin, which will have a valid type set.
Pass CreateContextResolverPass();

} // namespace bpftrace::ast
