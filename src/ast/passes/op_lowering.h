#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateOpLoweringPass();

} // namespace bpftrace::ast
