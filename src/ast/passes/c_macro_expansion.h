#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateCMacroExpansionPass();

} // namespace bpftrace::ast
