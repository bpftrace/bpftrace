#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Lifts the context into a local variable, which can then be transparently
// passed through anonymous functions, loops, etc.
//
// Note that after this pass, the `ctx` builtin still be must be handled and
// resolved correctly but it should only be accessed once per probe.
Pass CreateLiftContextPass();

} // namespace bpftrace::ast
