#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateFoldLiteralsPass();

} // namespace bpftrace::ast
