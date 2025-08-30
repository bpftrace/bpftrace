#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateComparisonExpansionPass();

} // namespace bpftrace::ast
