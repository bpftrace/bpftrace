#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// This pass issues errors and warnings about basic variable usage
// - variable was never assigned to
// - variable was used before assignment
// - variable declaration shadows another variable
// - variable is not defined
Pass CreateVariablePreCheckPass();

} // namespace bpftrace::ast
