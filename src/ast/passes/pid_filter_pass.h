#pragma once

#include "ast/pass_manager.h"

namespace bpftrace {
namespace ast {

Pass CreatePidFilterPass();

} // namespace ast
} // namespace bpftrace
