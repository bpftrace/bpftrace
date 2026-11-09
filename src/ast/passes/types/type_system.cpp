#include "ast/passes/types/type_system.h"
#include "ast/context.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/clang_build.h"
#include "ast/passes/printer.h"
#include "ast/passes/types/type_map.h"

namespace bpftrace::ast {

// Builds a `Function` for each member of the helpers struct, from the member's
// function pointer type. The types are added on top of the kernel types so
// that forward declared structs resolve to the kernel's definition.
static Result<std::map<std::string, btf::Function>> load_helpers(
    const btf::Types &kernel,
    const std::string &object)
{
  auto parsed = btf::Types::parse(static_cast<const void *>(object.data()),
                                  object.size());
  if (!parsed) {
    return parsed.takeError();
  }
  btf::Types helpers(kernel);
  auto ok = helpers.append(*parsed);
  if (!ok) {
    return ok.takeError();
  }
  auto members = helpers.lookup<btf::Struct>(
      std::string(BitcodeModules::HELPERS_STRUCT));
  if (!members) {
    return members.takeError();
  }
  auto fields = members->fields();
  if (!fields) {
    return fields.takeError();
  }
  std::map<std::string, btf::Function> funcs;
  for (const auto &[name, field] : *fields) {
    btf::AnyType type = field.type;
    if (type.is<btf::Const>()) {
      auto inner = type.as<btf::Const>().type();
      if (!inner) {
        return inner.takeError();
      }
      type = *inner;
    }
    if (!type.is<btf::Pointer>()) {
      continue;
    }
    auto proto = type.as<btf::Pointer>().element_type();
    if (!proto) {
      return proto.takeError();
    }
    if (!proto->is<btf::FunctionProto>()) {
      continue;
    }
    auto func = helpers.add<btf::Function>(name,
                                           btf::Function::Linkage::Global,
                                           proto->as<btf::FunctionProto>());
    if (!func) {
      return func.takeError();
    }
    funcs.emplace(name, std::move(*func));
  }
  return funcs;
}

Pass CreateTypeSystemPass()
{
  auto fn = [](ASTContext &ast,
               FunctionInfo &func_info,
               BitcodeModules &bm) -> Result<TypeMetadata> {
    TypeMetadata result;

    // For now, we simply build a single type system that covers all the
    // external imports and standard library.
    // Eventually we want to load in a base type system
    // that is different for each of the probes.
    std::optional<btf::Types> aggregate;
    auto kernel_types = func_info.kernel_info().load_btf("vmlinux");
    if (kernel_types) {
      result.kernel = std::move(*kernel_types);
    } else {
      consumeError(kernel_types.takeError());
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

    if (!bm.helpers_object.empty()) {
      auto helpers = load_helpers(result.kernel, bm.helpers_object);
      if (!helpers) {
        return helpers.takeError();
      }
      result.helpers = std::move(*helpers);
    }

    return result;
  };

  return Pass::create("TypeSystem", fn);
}

Pass CreateDumpTypesPass(std::ostream &out)
{
  auto fn = [&out](ASTContext &ast, TypeMetadata &tm, TypeMap &type_map) {
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
    ast::Printer printer(ast,
                         out,
                         ast::FormatMode::Debug,
                         ast::Printer::kDefaultWidth,
                         &type_map);
    printer.visit(ast.root);
  };
  return Pass::create("DumpTypes", fn);
}

} // namespace bpftrace::ast
