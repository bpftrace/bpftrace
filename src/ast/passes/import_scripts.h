#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Requires the `Imports` from the `CreateResolveRootImports` pass.
Pass CreateImportInternalScriptsPass();
Pass CreateImportExternalScriptsPass();

} // namespace bpftrace::ast
