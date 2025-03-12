#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateSemanticPass(bool listing = false);

} // namespace bpftrace::ast
