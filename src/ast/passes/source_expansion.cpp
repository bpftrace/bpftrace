#include "ast/ast.h"
#include "ast/passes/pid_filter_pass.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

namespace {

class SourceExpansionPass : public Visitor<SourceExpansionPass> {
public:
  explicit SourceExpansionPass(ASTContext &ast) : ast_(ast)
  {
  }

  using Visitor<SourceExpansionPass>::visit;
  void visit(Expression &expr);

private:
  ASTContext &ast_;
};

Location get_root_loc(Location current)
{
  while (true) {
    if (current->parent) {
      current = current->parent->loc;
      continue;
    }
    break;
  }
  return current;
}

} // namespace

void SourceExpansionPass::visit(Expression &expr)
{
  auto *builtin = expr.as<Builtin>();
  if (!builtin || (builtin->ident != "file" && builtin->ident != "line")) {
    Visitor<SourceExpansionPass>::visit(expr);
    return;
  }

  Location root_loc = get_root_loc(builtin->loc);

  if (builtin->ident == "file") {
    expr.value = ast_.make_node<String>(root_loc->filename(),
                                        Location(builtin->loc));
    return;
  }

  expr.value = ast_.make_node<Integer>(root_loc->line(),
                                       Location(builtin->loc));
}

Pass CreateSourceExpansionPass()
{
  return Pass::create("SourceExpansion", [](ASTContext &ast) {
    auto pid_filter = SourceExpansionPass(ast);
    pid_filter.visit(ast.root);
  });
};

} // namespace bpftrace::ast
