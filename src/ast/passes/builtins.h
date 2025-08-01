#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Fill in the values of all intrinsics.
Pass CreateBuiltinsPass();

} // namespace bpftrace::ast
