#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateProbeExpansionPass(bool listing = false);

} // namespace bpftrace::ast
