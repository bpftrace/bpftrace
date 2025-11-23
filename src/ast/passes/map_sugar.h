#pragma once

#include <unordered_map>

#include "ast/ast.h"
#include "ast/pass_manager.h"

namespace bpftrace::ast {

// MapMetadata contains metadata related to the sugared maps.
//
// For now, this is whether they are used as scalars. In the future, this may
// be used as the basis for `MapInfo`, which can be propagated and used by
// passes, rather than being mutated within the BPFtrace object.
//
// Additionally we track scalar/non-scalar map errors here but defer actually
// issuing the errors on the nodes until a later pass as they may removed if
// they are inside branch that is pruned at compile time
class MapMetadata : public ast::State<"map-metadata"> {
public:
  std::unordered_map<std::string, bool> scalar;
  std::unordered_set<Node *> bad_scalar_access;
  std::unordered_set<Node *> bad_indexed_access;
  std::unordered_set<Node *> bad_scalar_call;
  std::unordered_set<Node *> bad_indexed_call;
  std::unordered_set<Node *> bad_iterator;
};

const std::unordered_set<std::string>& getAssignRewriteFuncs();
const std::unordered_set<std::string>& getRawMapArgFuncs();

Pass CreateMapSugarPass();

} // namespace bpftrace::ast
