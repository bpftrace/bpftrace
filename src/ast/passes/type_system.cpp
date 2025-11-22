#include "ast/passes/type_system.h"
#include "ast/context.h"
#include "ast/passes/clang_build.h"

namespace bpftrace::ast {

Result<OK> build_types(ASTContext &ast,
                       BitcodeModules &bm,
                       TypeMetadata &type_metadata)
{
  // For now, we simply build a single type system that covers all the
  // external imports and standard library. In theory, this should be rebased
  // on top of the individual probe type system (coming from the kernel,
  // module or user binary).
  for (const auto &module : bm.modules) {
    if (type_metadata.parsed_modules.contains(module.name)) {
      continue;
    }

    type_metadata.parsed_modules.insert(module.name);
    auto btf = btf::Types::parse(
        static_cast<const void *>(module.object.data()), module.object.size());
    if (!btf) {
      // If we encounter some error parsing BTF, add it to the specific
      // import directly. If there is no BTF (e.g. an empty C file), then
      // we can just suppress the warning.
      auto ok = handleErrors(std::move(btf),
                             [&](const btf::ParseError &parse_err) {
                               if (parse_err.error_code() != ENODATA) {
                                 auto &diag = ast.diagnostics().addWarning(
                                     module.loc);
                                 diag << "Failed to parse BTF data: "
                                      << strerror(parse_err.error_code());
                               }
                             });
      if (!ok) {
        return ok.takeError();
      }
      continue; // Skip this file.
    }
    auto ok = type_metadata.global.append(*btf);
    if (!ok) {
      return ok.takeError();
    }
  }

  return OK();
}

Pass CreateTypeSystemPass()
{
  auto fn = [](ASTContext &ast, BitcodeModules &bm) -> Result<TypeMetadata> {
    TypeMetadata result;

    auto ok = build_types(ast, bm, result);
    if (!ok) {
      return ok.takeError();
    }

    return result;
  };

  return Pass::create("TypeSystem", fn);
}

Pass CreateDumpTypesPass(std::ostream &out)
{
  auto fn = [&out](TypeMetadata &tm) {
    for (const auto &type : tm.global) {
      if (!type.is<btf::Function>()) {
        continue;
      }
      out << type.as<btf::Function>() << "\n";
    }
    for (const auto &type : tm.global) {
      if (!type.is<btf::Var>()) {
        continue;
      }
      out << type.as<btf::Var>() << "\n";
    }
  };
  return Pass::create("DumpTypes", fn);
}

} // namespace bpftrace::ast
