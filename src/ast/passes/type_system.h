#pragma once

#include <unordered_map>

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "btf/btf.h"

namespace bpftrace::ast {

// TypeMetadata contains metadata related to the set of external types that are
// available to each probe. Note that this does not currently cover any of the
// existing `SizedType` implementations.
class TypeMetadata : public ast::State<"type-metadata"> {
public:
  std::unordered_map<Probe *, btf::Types> types;
};

Pass CreateTypeSystemPass();
Pass CreateDumpTypesPass(std::ostream &out);

} // namespace bpftrace::ast
