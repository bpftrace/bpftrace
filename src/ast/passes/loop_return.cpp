#include "ast/passes/loop_return.h"
#include "ast/ast.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class LoopReturn : public Visitor<LoopReturn> {
public:
  LoopReturn(ASTContext &ast) : ast_(ast) {};

  using Visitor<LoopReturn>::visit;

  void visit(Probe &probe);
  void visit(For &for_loop);
  void visit(While &while_loop);
  void visit(Statement &stmt);

private:
  Variable *get_return_var(const Node &node)
  {
    return ast_.make_node<Variable>("__return_value", Location(node.loc));
  }
  Variable *get_return_set_var(const Node &node)
  {
    return ast_.make_node<Variable>("__return_value_set", Location(node.loc));
  }

  ASTContext &ast_;
  int loop_depth_ = 0;
  std::optional<bool> loop_return_;
};

} // namespace

void LoopReturn::visit(For &for_loop)
{
  loop_depth_++;
  Visitor<LoopReturn>::visit(for_loop);
  loop_depth_--;
}

void LoopReturn::visit(While &while_loop)
{
  loop_depth_++;
  Visitor<LoopReturn>::visit(while_loop);
  loop_depth_--;
}

void LoopReturn::visit(Statement &stmt)
{
  // Recursively visit the block statements.
  Visitor<LoopReturn>::visit(stmt);

  // First see if we have any loop statements, because we will inject an
  // additional return into those statements if needed. This may be rewritten
  // below, but only if this is within an inner loop.
  //
  // Consider that this takes:
  //
  // for (...) { }
  //
  // And turns it into:
  //
  // { for (...) { } if (__return_value_ret) { return __return_value; } }
  //
  // The return may be subsequently rewritten below, if inside a loop.
  bool is_loop = stmt.is<For>() || stmt.is<While>();
  if (is_loop && loop_return_.has_value()) {
    std::vector<Statement> ret_stmts;
    if (loop_depth_ > 0) {
      // We're still in a loop, so just break.
      ret_stmts.emplace_back(
          ast_.make_node<Jump>(JumpType::BREAK, Location(stmt.node().loc)));
    } else if (loop_return_.value()) {
      // The value was set within the loop, so return it.
      ret_stmts.emplace_back(ast_.make_node<Jump>(JumpType::RETURN,
                                                  get_return_var(stmt.node()),
                                                  Location(stmt.node().loc)));
    } else {
      // The value was not set within the loop, so skip it.
      ret_stmts.emplace_back(
          ast_.make_node<Jump>(JumpType::RETURN, Location(stmt.node().loc)));
    }
    // Make an if contingent on the return value being set, and break
    // from this local loop if that is the case.
    auto *ret_block = ast_.make_node<Block>(std::move(ret_stmts),
                                            Location(stmt.node().loc));
    auto *ret_if = ast_.make_node<If>(
        Expression(get_return_set_var(stmt.node())),
        ret_block,
        ast_.make_node<Block>(std::vector<Statement>({}),
                              Location(stmt.node().loc)),
        Location(stmt.node().loc));
    auto *block = ast_.make_node<Block>(
        std::vector<Statement>({ stmt, ret_if }), Location(stmt.node().loc));
    stmt = Statement(block); // Replace with the compound block.
  } else if (auto *jmp = stmt.as<Jump>()) {
    // This rewrites any return statements in a loop as something that will
    // set the return value and then break the loop. Combined with the above,
    // which checks this *outside* the loop and injects a return (possibly
    // rewritten here if inside an inner loop), we have control flow logic
    // that will be captured by the automatic context.
    if (loop_depth_ > 0 && jmp->ident == JumpType::RETURN) {
      if (!loop_return_.has_value()) {
        loop_return_ = jmp->return_value.has_value();
      } else if (loop_return_.value() != jmp->return_value.has_value()) {
        // We cannot handle this case, but it's a more general error.
        jmp->addError() << "Return value used in loop is inconsistent";
        return;
      }
      std::vector<Statement> ret_stmts;
      if (loop_return_.value() && jmp->return_value.has_value()) {
        ret_stmts.emplace_back(
            ast_.make_node<AssignVarStatement>(get_return_var(stmt.node()),
                                               jmp->return_value.value(),
                                               Location(jmp->loc)));
      }
      ret_stmts.emplace_back(ast_.make_node<AssignVarStatement>(
          get_return_set_var(stmt.node()),
          ast_.make_node<Integer>(1, Location(jmp->loc)),
          Location(jmp->loc)));
      ret_stmts.emplace_back(
          ast_.make_node<Jump>(JumpType::BREAK, Location(jmp->loc)));
      auto *block = ast_.make_node<Block>(
          std::vector<Statement>(std::move(ret_stmts)), Location(jmp->loc));
      stmt = Statement(block);
    }
  }
}

void LoopReturn::visit(Probe &probe)
{
  Visitor<LoopReturn>::visit(probe);

  if (loop_return_.has_value()) {
    // Declare the return variables at the top of the probe. These actually
    // need to supercede all the other statements in the block.
    if (loop_return_.value()) {
      auto *ret_var_decl = ast_.make_node<VarDeclStatement>(
          get_return_var(probe), Location(probe.loc));
      probe.block->stmts.insert(probe.block->stmts.begin(),
                                Statement(ret_var_decl));
    }
    auto *ret_set_var_decl = ast_.make_node<VarDeclStatement>(
        get_return_set_var(probe), CreateInt8(), Location(probe.loc));
    probe.block->stmts.insert(probe.block->stmts.begin(),
                              Statement(ret_set_var_decl));
    loop_return_.reset();
  }
}

Pass CreateLoopReturnPass()
{
  auto fn = [](ASTContext &ast) {
    LoopReturn lr(ast);
    lr.visit(ast.root);
  };

  return Pass::create("LoopReturn", fn);
}

} // namespace bpftrace::ast
