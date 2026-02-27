#include "ast/passes/types/type_system.h"
#include "ast/context.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/clang_build.h"
#include "ast/passes/printer.h"

namespace bpftrace::ast {

Pass CreateTypeSystemPass()
{
  auto fn = [](ASTContext &ast,
               FunctionInfo &func_info,
               BitcodeModules &bm) -> Result<TypeMetadata> {
    TypeMetadata result;

    // For now, we simply build a single type system that covers all the
    // external imports and standard library. For now, we load in all the
    // kernel types, but in theory this should load in a base type system
    // that is different for each of the probes.
    std::optional<btf::Types> aggregate;
    auto kernel_types = func_info.kernel_info().load_btf("vmlinux");
    if (kernel_types) {
      aggregate.emplace(std::move(*kernel_types));
    }

    for (const auto &module : bm.modules) {
      auto btf = btf::Types::parse(static_cast<const void *>(
                                       module.object.data()),
                                   module.object.size());
      if (!btf) {
        // If we encounter some error parsing BTF, add it to the specific
        // import directly. If there is no BTF (e.g. an empty C file), then
        // we can just suppress the warning.
        auto err = handleErrors(std::move(btf),
                                [&](const btf::ParseError &parse_err) {
                                  if (parse_err.error_code() != ENODATA) {
                                    auto &diag = ast.diagnostics().addWarning(
                                        module.loc);
                                    diag << "Failed to parse BTF data: "
                                         << strerror(parse_err.error_code());
                                  }
                                });
        if (!err) {
          return err.takeError();
        }
        continue; // Skip this file.
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
  auto fn = [&out](ASTContext &ast, TypeMetadata &tm) {
    out << "// Functions\n";
    for (const auto &type : tm.global) {
      if (!type.is<btf::Function>()) {
        continue;
      }
      out << "// " << type.as<btf::Function>() << "\n";
    }
    out << "// Variables\n";
    for (const auto &type : tm.global) {
      if (!type.is<btf::Var>()) {
        continue;
      }
      out << "// " << type.as<btf::Var>() << "\n";
    }
    out << "// Program\n";
    ast::Printer printer(ast, out, ast::FormatMode::Debug);
    printer.visit(ast.root);
  };
  return Pass::create("DumpTypes", fn);
}

} // namespace bpftrace::ast
