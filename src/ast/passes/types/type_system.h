#pragma once

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "btf/btf.h"

namespace bpftrace::ast {

// TypeMetadata holds the external BTF types: `global` is built from the
// standard library and imported C modules, `kernel` is loaded from vmlinux,
// and `helpers` holds the prototypes of the BPF helpers, if there are
// `helper::` calls. It does not cover any of the existing `SizedType`
// implementations.
//
// Currently this is only consulted to resolve calls to external functions:
// `kfunc::` calls are looked up in `kernel`, `helper::` calls in `helpers`
// and all other calls in `global` (see `for_call()`). In the future this may
// be extended to "per-probe" types, e.g. the types loaded per kernel module or
// associated with user binaries.
class TypeMetadata : public ast::State<"type-metadata"> {
public:
  const btf::Types &for_call(const Call &call) const
  {
    switch (call.ns) {
      case Call::Namespace::KFunc:
        return kernel;
      case Call::Namespace::Helper:
        return helpers;
      case Call::Namespace::Default:
        break;
    }
    return global;
  }

  const btf::Types *kernel_for_call(const Call &call) const
  {
    return call.is_kfunc() ? nullptr : &kernel;
  }

  btf::Types global;
  btf::Types kernel;
  btf::Types helpers;
};

Pass CreateTypeSystemPass();
Pass CreateDumpTypesPass(std::ostream &out);

} // namespace bpftrace::ast
