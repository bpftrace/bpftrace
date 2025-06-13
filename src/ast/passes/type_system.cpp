#include <unordered_map>

#include "ast/ast.h"
#include "ast/passes/clang_build.h"
#include "ast/passes/type_system.h"

namespace bpftrace::ast {

Pass CreateTypeSystemPass()
{
  auto fn = [](BitcodeModules &bm) -> Result<TypeMetadata> {
    TypeMetadata result;

    // For now, we simply build a single type system that covers all the
    // external imports and standard library. In theory, this should be rebased
    // on top of the individual probe type system (coming from the kernel,
    // module or user binary).
    std::optional<btf::Types> aggregate;
    for (const auto &s : bm.objects) {
      auto btf = btf::Types::parse(static_cast<const void *>(s.data()),
                                   s.size());
      if (!btf) {
        return btf.takeError();
      }
      if (!aggregate) {
        aggregate.emplace(std::move(*btf));
      } else {
        auto ok = aggregate->append(*btf);
        if (!ok) {
          return ok.takeError();
        }
      }
    }
    if (aggregate) {
      result.global = std::move(*aggregate);
    }

    return result;
  };

  return Pass::create("TypeSystem", fn);
}

Pass CreateDumpTypesPass(std::ostream &out)
{
  auto fn = [&out](TypeMetadata &tm) {
    for (const btf::Function &func : tm.global | btf::filter<btf::Function>()) {
      out << func << "\n";
    }
    for (const btf::Var &var : tm.global | btf::filter<btf::Var>()) {
      out << var << "\n";
    }
  };
  return Pass::create("DumpTypes", fn);
}

} // namespace bpftrace::ast
