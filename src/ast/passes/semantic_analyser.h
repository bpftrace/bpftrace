#pragma once

#include "ast/pass_manager.h"

namespace bpftrace {
namespace ast {

Pass CreateSemanticPass(bool listing = false);

} // namespace ast
} // namespace bpftrace
