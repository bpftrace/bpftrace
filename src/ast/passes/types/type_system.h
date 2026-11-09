#pragma once

#include <map>
#include <string>

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "btf/btf.h"

namespace bpftrace::ast {

// TypeMetadata holds the external BTF types: `global` is built from the
// standard library and imported C modules, `kernel` is loaded from vmlinux,
// and `helpers` holds the prototypes of the BPF helpers used by `helper::`
// calls. It does not cover any of the existing `SizedType` implementations.
//
// Currently this is only consulted to resolve calls to external functions:
// `kfunc::` calls are looked up in `kernel`, `helper::` calls in `helpers`
// and all other calls in `global` (see `lookup_function()`). In the future
// this may be extended to "per-probe" types, e.g. the types loaded per kernel
// module or associated with user binaries.
//
// `helpers` is keyed by name rather than looked up in BTF because its types
// are built on top of the kernel types, which contain type-erased functions
// with the same names as the helpers.
class TypeMetadata : public ast::State<"type-metadata"> {
public:
  Result<btf::Function> lookup_function(const Call &call) const
  {
    switch (call.ns) {
      case Call::Namespace::KFunc:
        return kernel.lookup<btf::Function>(call.func);
      case Call::Namespace::Helper: {
        auto it = helpers.find(call.func);
        if (it == helpers.end()) {
          return make_error<btf::UnknownType>(call.func);
        }
        return it->second;
      }
      case Call::Namespace::Default:
        break;
    }
    return global.lookup<btf::Function>(call.func);
  }

  btf::Types global;
  btf::Types kernel;
  std::map<std::string, btf::Function> helpers;
};

Pass CreateTypeSystemPass();
Pass CreateDumpTypesPass(std::ostream &out);

} // namespace bpftrace::ast
