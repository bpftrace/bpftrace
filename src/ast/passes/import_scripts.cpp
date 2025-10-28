#include <algorithm>

#include "ast/ast.h"
#include "ast/passes/import_scripts.h"
#include "ast/passes/resolve_imports.h"

namespace bpftrace::ast {

static void import_ast(ASTContext &ast, Node &node, const ASTContext &other)
{
  // The ordering of all probes is reversed before and after appending,
  // in order to provide a partial ordering over imports. Consider the
  // left node import -- this will wind up being the first thing initialized.
  std::ranges::reverse(ast.root->probes);

  // Clone all map declarations, subfunctions, etc. into the primary AST.
  // Note that we may choose not to inline all definitions in the future, and
  // define that namespace-based resolution is used for e.g. macro expansion,
  // function matching, etc. But for now, we just support a trivial
  // expansion.
  ast.diagnostics().add(std::move(other.diagnostics()));
  if (other.root) {
    for (const auto &stmt : other.root->c_statements) {
      ast.root->c_statements.push_back(clone(ast, node.loc, stmt));
    }
    for (const auto &decl : other.root->map_decls) {
      ast.root->map_decls.push_back(clone(ast, node.loc, decl));
    }
    for (const auto &fn : other.root->functions) {
      ast.root->functions.push_back(clone(ast, node.loc, fn));
    }
    for (const auto &macro : other.root->macros) {
      ast.root->macros.push_back(clone(ast, node.loc, macro));
    }
    for (const auto &probe : other.root->probes) {
      ast.root->probes.push_back(clone(ast, node.loc, probe));
    }
  }

  // See above. We re-reverse the set of probes available to provide the
  // intended partial ordering.
  std::ranges::reverse(ast.root->probes);
}

Pass CreateImportExternalScriptsPass()
{
  return Pass::create("ImportExternalScripts",
                      [](ASTContext &ast, Imports &imports) {
                        for (const auto &[name, obj] : imports.scripts) {
                          if (!obj.internal) {
                            import_ast(ast, obj.node, obj.ast);
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
                            import_ast(ast, obj.node, obj.ast);
                          }
                        }
                      });
}

} // namespace bpftrace::ast
