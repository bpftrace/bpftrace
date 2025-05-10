#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Requires the `Imports` from the `CreateResolveImports` pass.
Pass CreateImportScriptsPass();

} // namespace bpftrace::ast
