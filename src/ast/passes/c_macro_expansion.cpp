#include <algorithm>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/c_macro_expansion.h"
#include "ast/visitor.h"
#include "clang_parser.h"
#include "driver.h"
#include "util/strings.h"

namespace bpftrace::ast {

class CMacroExpander : public Visitor<CMacroExpander> {
public:
  CMacroExpander(ASTContext &ast, CDefinitions &c_definitions)
      : ast_(ast), c_definitions_(c_definitions) {};

  using Visitor<CMacroExpander>::visit;
  void visit(Expression &expr);

private:
  ASTContext &ast_;
  CDefinitions &c_definitions_;
  std::vector<std::string> active_;
};

void CMacroExpander::visit(Expression &expr)
{
  // N.B. We only support raw identifier macros. The way expansion works is
  // that we see if an expression is a bare identifier, then attempt expansion
  // recurisvely.
  if (auto *ident = expr.as<Identifier>()) {
    if (c_definitions_.macros.contains(ident->ident)) {
      const auto &value = c_definitions_.macros[ident->ident];

      // Check for recursion.
      if (std::ranges::find(active_, ident->ident) != active_.end()) {
        ident->addError() << "Macro recursion: "
                          << util::str_join(active_, "->");
        return;
      }

      // Parse just the macro as an expression.
      ASTContext macro(ident->ident, value);
      Driver driver(macro);
      auto expanded = driver.parse_expr();
      if (!expanded) {
        ident->addError() << "unable to expand macro as an expression: "
                          << value;
        return;
      }

      // Expand the macro expression in place.
      expr.value = clone(ast_, expanded->value, ident->loc);

      // Recursively visit the potentially expanded expression, ensuring that
      // we can catch recursive expansion, per above.
      active_.emplace_back(ident->ident);
      Visitor<CMacroExpander>::visit(expr);
      active_.pop_back();
      return;
    }
  }

  // Expand normally.
  Visitor<CMacroExpander>::visit(expr);
}

Pass CreateCMacroExpansionPass()
{
  auto fn = [](ASTContext &ast, CDefinitions &c_definitions) {
    CMacroExpander expander(ast, c_definitions);
    expander.visit(ast.root);
  };

  return Pass::create("CMacroExpansion", fn);
}

} // namespace bpftrace::ast
