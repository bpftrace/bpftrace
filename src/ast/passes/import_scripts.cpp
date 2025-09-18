#include "ast/passes/import_scripts.h"
#include "ast/ast.h"
#include "ast/passes/resolve_imports.h"

namespace bpftrace::ast {

static void import_ast(ASTContext &ast, const ASTContext &other)
{
  // Clone all map declarations, subfunctions, etc. into the primary AST.
  // Note that we may choose not to inline all definitions in the future, and
  // define that namespace-based resolution is used for e.g. macro expansion,
  // function matching, etc. But for now, we just support a trivial
  // expansion.
  ast.diagnostics().add(std::move(other.diagnostics()));
  if (other.root) {
    for (const auto &stmt : other.root->c_statements) {
      ast.root->c_statements.push_back(clone(ast, stmt));
    }
    for (const auto &decl : other.root->map_decls) {
      ast.root->map_decls.push_back(clone(ast, decl));
    }
    for (const auto &fn : other.root->functions) {
      ast.root->functions.push_back(clone(ast, fn));
    }
    for (const auto &macro : other.root->macros) {
      ast.root->macros.push_back(clone(ast, macro));
    }
    for (const auto &probe : other.root->probes) {
      ast.root->probes.push_back(clone(ast, probe));
    }
  }
}

Pass CreateImportExternalScriptsPass()
{
  return Pass::create("ImportExternalScripts",
                      [](ASTContext &ast, Imports &imports) {
                        for (const auto &[name, obj] : imports.scripts) {
                          if (!obj.internal) {
                            import_ast(ast, obj.ast);
                          }
                        }
                      });
}

Pass CreateImportInternalScriptsPass()
{
  return Pass::create("ImportInternalScripts",
                      [](ASTContext &ast, Imports &imports) {
                        for (const auto &[name, obj] : imports.scripts) {
                          if (obj.internal) {
                            import_ast(ast, obj.ast);
                          }
                        }
                      });
}

} // namespace bpftrace::ast
