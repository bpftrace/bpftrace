#pragma once

#include <unordered_map>

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "btf/btf.h"

namespace bpftrace::ast {

// TypeMetadata contains metadata related to the set of external types that are
// available to each probe. Note that this does not currently cover any of the
// existing `SizedType` implementations.
//
// For now, this consistent of a single `global` set of types that are
// available from the extern interop modules. In the future this may be
// extended to "per-probe" types, e.g. the types loaded from the kernel, per
// module or associated with user binaries.
class TypeMetadata : public ast::State<"type-metadata"> {
public:
  btf::Types global;
};

Pass CreateTypeSystemPass();
Pass CreateDumpTypesPass(std::ostream &out);

} // namespace bpftrace::ast
