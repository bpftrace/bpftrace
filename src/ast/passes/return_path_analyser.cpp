#include <algorithm>

#include "ast/passes/return_path_analyser.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class ReturnPathAnalyser : public Visitor<ReturnPathAnalyser, bool> {
public:
  // visit methods return true iff all return paths of the analyzed code
  // (represented by the given node) return a value.
  using Visitor<ReturnPathAnalyser, bool>::visit;
  bool visit(Program &prog);
  bool visit(Subprog &subprog);
  bool visit(Jump &jump);
  bool visit(If &if_node);
};

} // namespace

bool ReturnPathAnalyser::visit(Program &prog)
{
  return std::ranges::all_of(prog.functions,
                             [this](auto *subprog) { return visit(*subprog); });
}

bool ReturnPathAnalyser::visit(Subprog &subprog)
{
  if (subprog.return_type.IsVoidTy())
    return true;

  for (auto &stmt : subprog.stmts) {
    if (visit(stmt))
      return true;
  }
  subprog.addError() << "Not all code paths returned a value";
  return false;
}

bool ReturnPathAnalyser::visit(Jump &jump)
{
  return jump.ident == JumpType::RETURN;
}

bool ReturnPathAnalyser::visit(If &if_node)
{
  bool result = false;
  for (auto &stmt : if_node.if_block->stmts) {
    if (visit(stmt))
      result = true;
  }
  if (!result) {
    // if block has no return
    return false;
  }

  // True if both blocks have a return.
  // False if else block has no return (or there is no else block).
  return std::ranges::any_of(if_node.else_block->stmts,
                             [this](auto &stmt) { return visit(stmt); });
}

Pass CreateReturnPathPass()
{
  auto fn = [](ASTContext &ast) {
    ReturnPathAnalyser return_path;
    return_path.visit(ast.root);
  };

  return Pass::create("ReturnPath", fn);
}

} // namespace bpftrace::ast
