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
  bool visit(Ternary &ternary);
  bool visit(Block &block);
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

  if (!visit(subprog.block)) {
    subprog.addError() << "Not all code paths returned a value";
    return false;
  }

  return true;
}

bool ReturnPathAnalyser::visit(Jump &jump)
{
  return jump.ident == JumpType::RETURN;
}

bool ReturnPathAnalyser::visit(Ternary &ternary)
{
  return visit(ternary.left) && visit(ternary.right);
}

bool ReturnPathAnalyser::visit(Block &block)
{
  for (auto &stmt : block.stmts) {
    if (visit(stmt)) {
      return true;
    }
  }
  return false;
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
