#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateProbePrunePass();

} // namespace bpftrace::ast
