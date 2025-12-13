#include "ast/passes/loop_return.h"
#include "ast/ast.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class LoopReturn : public Visitor<LoopReturn> {
public:
  LoopReturn(ASTContext &ast) : ast_(ast) {};

  using Visitor<LoopReturn>::visit;

  template <typename T>
  void inject(T &node);

  void visit(Subprog &subprog);
  void visit(Probe &probe);
  void visit(For &for_loop);
  void visit(While &while_loop);
  void visit(Statement &stmt);

private:
  Variable *get_return_var(const Node &node)
  {
    return ast_.make_node<Variable>(node.loc, "__return_value");
  }
  Variable *get_return_set_var(const Node &node)
  {
    return ast_.make_node<Variable>(node.loc, "__return_value_set");
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
  // { for (...) { } if (__return_value_set) { return __return_value; } }
  //
  // The return may be subsequently rewritten below, if inside a loop.
  bool is_loop = stmt.is<For>() || stmt.is<While>();
  if (is_loop && loop_return_.has_value()) {
    std::vector<Statement> ret_stmts;
    if (loop_depth_ > 0) {
      // We're still in a loop, so just break.
      ret_stmts.emplace_back(
          ast_.make_node<Jump>(stmt.node().loc, JumpType::BREAK));
    } else if (loop_return_.value()) {
      // The value was set within the loop, so return it.
      ret_stmts.emplace_back(ast_.make_node<Jump>(stmt.node().loc,
                                                  JumpType::RETURN,
                                                  get_return_var(stmt.node())));
    } else {
      // The value was not set within the loop, so skip it.
      ret_stmts.emplace_back(
          ast_.make_node<Jump>(stmt.node().loc, JumpType::RETURN));
    }
    // Make an if contingent on the return value being set, and break
    // from this local loop if that is the case.
    auto *ret_block = ast_.make_node<BlockExpr>(stmt.node().loc,
                                                std::move(ret_stmts),
                                                ast_.make_node<None>(
                                                    stmt.node().loc));
    auto *ret_if = ast_.make_node<IfExpr>(stmt.node().loc,
                                          get_return_set_var(stmt.node()),
                                          ret_block,
                                          ast_.make_node<None>(
                                              stmt.node().loc));
    auto *ret_stmt = ast_.make_node<ExprStatement>(stmt.node().loc, ret_if);
    auto *block = ast_.make_node<BlockExpr>(
        stmt.node().loc,
        std::vector<Statement>({ stmt, ret_stmt }),
        ast_.make_node<None>(stmt.node().loc));
    auto *block_stmt = ast_.make_node<ExprStatement>(stmt.node().loc, block);
    stmt = block_stmt; // Replace with the compound block.
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
      if (jmp->return_value.has_value()) {
        ret_stmts.emplace_back(ast_.make_node<AssignVarStatement>(
            jmp->loc, get_return_var(stmt.node()), jmp->return_value.value()));
      }
      // This (and the below declaration, *should* be a boolean. Unfortunately,
      // the clang optimization passes are able to outsmart the by verifier by
      // short-circuiting the return value. The compiler knows that this value
      // contains either zero or one, and it is also the intended return value.
      //
      // if ($x == 1) { return 1; } else { return 0; }
      //
      //     gets transformed into:
      //
      // return $x;
      //
      // Unfortunately the verifier is *not* sure that this value is either
      // zero or one, and bails out:
      //
      // 190: (73) *(u8 *)(r8 +0) = r7         ; frame2: R7_w=1 R8=fp[0]-49 cb
      // 191: (bf) r0 = r7                     ; frame2: R0_w=1 R7_w=1 cb
      // 192: (95) exit
      // returning from callee:
      //  frame2: R0_w=1 R1_w=3 R2=scalar() R6=fp[1]-48 R7_w=1 R8=fp[0]-49
      //  R9=scalar(smin=smin32=0,smax=umax=smax32=umax32=1320,var_off=(0x0;
      //  0x7f8)) R10=fp0 fp-8=???????m fp-16=mmmmmmmm fp-24=mmmmmmmm cb
      // to caller at 124:
      //  frame1:
      //  R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=165,var_off=(0x0;
      //  0xff))
      //  R1=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=127,var_off=(0x0;
      //  0x7f)) R2=func() R3=fp-48 R4=0 R6=0 R7=fp[0]-49
      //  R8=scalar(smin=smin32=0,smax=umax=smax32=umax32=1320,var_off=(0x0;
      //  0x7f8)) R10=fp0 fp-32=scalar(id=8) fp-40=mmmmmmm1 fp-48=fp[0]-49 cb
      // 124: (85) call bpf_loop#181           ; frame1: R0_w=scalar() R6=0
      // R7=fp[0]-49
      // R8=scalar(smin=smin32=0,smax=umax=smax32=umax32=1320,var_off=(0x0;
      // 0x7f8)) R10=fp0 fp-32=scalar(id=8) fp-40=mmmmmmm1 fp-48=fp[0]-49 cb
      // 125: (bf) r1 = r0                     ; frame1: R0_w=scalar(id=9)
      // R1_w=scalar(id=9) cb 126: (67) r1 <<= 32                   ; frame1:
      // R1_w=scalar(smax=0x7fffffff00000000,umax=0xffffffff00000000,smin32=0,smax32=umax32=0,var_off=(0x0;
      // 0xffffffff00000000)) cb 127: (c7) r1 s>>= 32                  ; frame1:
      // R1_w=scalar(smin=0xffffffff80000000,smax=0x7fffffff) cb 128: (6d) if r6
      // s> r1 goto pc+2       ; frame1:
      // R1_w=scalar(smin=smin32=0,smax=umax=umax32=0x7fffffff,var_off=(0x0;
      // 0x7fffffff)) R6=0 cb 129: (71) r0 = *(u8 *)(r7 +0)         ; frame1:
      // R0_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0;
      // 0xff)) R7=fp[0]-49 cb 130: (95) exit At callback return the register R0
      // has smin=0 smax=255 should have been in [0, 1]
      //
      // We fix this by simply having a wider integer for this case, so we
      // check if the value is set to anything, and a cast is forced.
      ret_stmts.emplace_back(ast_.make_node<AssignVarStatement>(
          jmp->loc,
          get_return_set_var(stmt.node()),
          ast_.make_node<Integer>(jmp->loc, 1)));
      ret_stmts.emplace_back(ast_.make_node<Jump>(jmp->loc, JumpType::BREAK));
      auto *block = ast_.make_node<BlockExpr>(jmp->loc,
                                              std::move(ret_stmts),
                                              ast_.make_node<None>(jmp->loc));
      auto *block_stmt = ast_.make_node<ExprStatement>(jmp->loc, block);
      stmt = block_stmt; // As above, replace with the compound block.
    }
  }
}

template <typename T>
void LoopReturn::inject(T &node)
{
  loop_return_.reset();
  Visitor<LoopReturn>::visit(node);

  if (loop_return_.has_value()) {
    // Declare the return variables at the top of the probe. These actually
    // need to supercede all the other statements in the block.
    if (loop_return_.value()) {
      auto *ret_var_decl = ast_.make_node<VarDeclStatement>(
          node.loc, get_return_var(node), false);
      node.block->stmts.insert(node.block->stmts.begin(),
                               Statement(ret_var_decl));
    }
    auto *ret_set_var_decl = ast_.make_node<AssignVarStatement>(
        node.loc,
        get_return_set_var(node),
        ast_.make_node<Integer>(node.loc, 0));
    node.block->stmts.insert(node.block->stmts.begin(),
                             Statement(ret_set_var_decl));
  }
}

void LoopReturn::visit(Subprog &subprog)
{
  inject(subprog);
}

void LoopReturn::visit(Probe &probe)
{
  inject(probe);
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
