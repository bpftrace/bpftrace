#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Validate builtins that have probe-type restrictions before probe expansion
// merges probes (e.g. session expansion merging kprobe + kretprobe).
Pass CreatePreExpansionBuiltinsPass();

// Fill in the values of all intrinsics.
Pass CreateBuiltinsPass();

} // namespace bpftrace::ast
