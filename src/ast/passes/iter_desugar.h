#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateIterDesugarPass();

} // namespace bpftrace::ast
