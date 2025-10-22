#include <set>

#include "ast/ast.h"
#include "ast/passes/resolve_imports.h"
#include "ast/passes/stdlib_import.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

std::unordered_map<std::string, std::string> func_to_path = {
  { "__bpf_strnlen", "stdlib/strings" },
  { "__bpf_strnstr", "stdlib/strings" },
  { "__strerror", "stdlib/strings" },
};

class StdlibImport : public Visitor<StdlibImport> {
public:
  explicit StdlibImport(ASTContext &ast) : ast_(ast)
  {
  }

  using Visitor<StdlibImport>::visit;
  void visit(Call &call);
  void visit(Probe &probe);

  const std::unordered_set<std::string> &get_paths()
  {
    return stdlib_paths_;
  }

private:
  ASTContext &ast_;
  std::unordered_set<std::string> stdlib_paths_;
};

void StdlibImport::visit(Call &call)
{
  for (auto &varg : call.vargs) {
    visit(varg);
  }
  auto found = func_to_path.find(call.func);
  if (found != func_to_path.end()) {
    stdlib_paths_.insert(found->second);
  }
}

void StdlibImport::visit(Probe &probe)
{
  for (auto *ap : probe.attach_points) {
    if (probetype(ap->provider) == ProbeType::usdt) {
      stdlib_paths_.insert("stdlib/usdt");
      break;
    }
  }
  visit(probe.attach_points);
  visit(probe.block);
}

} // namespace

// This is so we can be more selective about standard library bpf.c files
// that possibly bloat the resulting ELF file/binary
Pass CreateStdlibImportPass()
{
  return Pass::create("StdlibImport",
                      [](ASTContext &ast, Imports &imports) -> Result<> {
                        StdlibImport stdlib_import(ast);
                        stdlib_import.visit(ast.root);

                        for (const auto &path : stdlib_import.get_paths()) {
                          auto ok = imports.import_any(*ast.root, path);
                          if (!ok) {
                            return ok;
                          }
                        }

                        return OK();
                      });
}

} // namespace bpftrace::ast
