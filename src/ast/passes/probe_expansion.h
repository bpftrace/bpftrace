#pragma once

#include "ast/pass_manager.h"
#include "probe_types.h"

namespace bpftrace::ast {

Pass CreateProbeExpansionPass(std::unordered_set<ProbeType>&& probe_types = {
    ProbeType::fentry,
    ProbeType::fexit,
    ProbeType::rawtracepoint,
    ProbeType::uprobe,
});

} // namespace bpftrace::ast
