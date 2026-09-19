#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Validate builtins that have probe-type restrictions before probe expansion
// merges probes (e.g. session expansion merging kprobe + kretprobe).
Pass CreatePreExpansionBuiltinsPass();

// Expand builtins that must be available before literal folding, i.e. those
// whose value does not depend on probe expansion. A builtin only works in an
// `if comptime` condition if it is folded here, as the untaken branch is
// otherwise still validated by every pass up to the type resolver.
Pass CreatePreFoldBuiltinsPass();

// Fill in the values of all intrinsics.
Pass CreateBuiltinsPass();

} // namespace bpftrace::ast
