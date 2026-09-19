#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Validate builtins that have probe-type restrictions before probe expansion
// merges probes (e.g. session expansion merging kprobe + kretprobe).
Pass CreatePreExpansionBuiltinsPass();

// Expand builtins that can be folded without code generation, then re-fold
// literals exposed by that expansion so comptime conditions can be pruned.
Pass CreateBuiltinsPass();

} // namespace bpftrace::ast
