#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateProbeExpansionPass();

} // namespace bpftrace::ast
