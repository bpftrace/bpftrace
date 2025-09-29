#pragma once

#include <unordered_map>

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// MapMetadata contains metadata related to the sugared maps.
//
// For now, this is whether they are used as scalars. In the future, this may
// be used as the basis for `MapInfo`, which can be propagated and used by
// passes, rather than being mutated within the BPFtrace object.
class MapMetadata : public ast::State<"map-metadata"> {
public:
  std::unordered_map<std::string, bool> scalar;
};

const std::unordered_set<std::string>& getAssignRewriteFuncs();

Pass CreateMapSugarPass();

} // namespace bpftrace::ast
