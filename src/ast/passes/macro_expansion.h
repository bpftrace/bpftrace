#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateMacroExpansionPass();

} // namespace bpftrace::ast
