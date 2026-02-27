#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// This pass runs early validation checks that do not depend on type
// information. It is composed of three separate visitors:
//
// VariablePreCheck:
//   - variable was never assigned to
//   - variable was used before assignment
//   - variable declaration shadows another variable
//   - variable is not defined
//
// CallPreCheck:
//   - function call argument count validation
//   - literal/structural validation per function
//   - safe mode checks
//   - probe availability checks
//   - string length checks
//   - unroll validation
Pass CreatePreTypeCheckPass();

} // namespace bpftrace::ast
