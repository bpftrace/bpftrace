#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateRecursionCheckPass();

} // namespace bpftrace::ast
