#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

Pass CreateMapAssignTransformPass();

} // namespace bpftrace::ast
