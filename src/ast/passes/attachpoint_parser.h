#pragma once

#include <optional>
#include <sstream>
#include <vector>

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "bpftrace.h"

namespace bpftrace::ast {

// For each `*Probe` in the original program, a list of unique attachpoint
// instances will be generated.
class AttachPointMap {
public:
  std::map<Probe *, std::vector<std::unique_ptr<Probe>>> instances;
};

Pass CreateParseAttachpointsPass();

} // namespace bpftrace::ast
