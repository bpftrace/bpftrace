#pragma once

#include "ast/pass_manager.h"
#include "util/result.h"

namespace bpftrace {

Result<OK> benchmark(ast::PassManager &mgr);

} // namespace bpftrace
