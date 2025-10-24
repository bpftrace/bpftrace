#include "ast/passes/control_flow_analyser.h"
#include "ast/ast.h"
#include "ast/context.h"
#include "ast/visitor.h"
#include "util/type_name.h"

namespace bpftrace::ast {

namespace {

class ExitReturn : public Visitor<ExitReturn> {
public:
  ExitReturn(ASTContext &ast) : ast_(ast) {};
  using Visitor<ExitReturn>::visit;
  void visit(Expression &expr);

private:
  ASTContext &ast_;
};

template <util::TypeName name, JumpType... Ts>
class JumpDisallowed : public Visitor<JumpDisallowed<name, Ts...>> {
public:
  using Visitor<JumpDisallowed>::visit;
  void visit([[maybe_unused]] Subprog &subprog)
  {
    JumpDisallowed<"function", JumpType::BREAK, JumpType::CONTINUE>().visit(
        subprog.block);
  }
  void visit([[maybe_unused]] For &f)
  {
    JumpDisallowed<"for-loop", JumpType::RETURN>().visit(f.block);
  }
  void visit([[maybe_unused]] While &w)
  {
    // If the while is inside a control flow where return is disallowed (e.g.
    // for) then it continues to be disallowed and vice versa.
    if constexpr ((... || (Ts == JumpType::RETURN))) {
      JumpDisallowed<"while-loop", JumpType::RETURN>().visit(w.block);
    } else {
      JumpDisallowed<"while-loop">().visit(w.block);
    }
  }
  void visit(Macro &macro)
  {
    JumpDisallowed<"macro",
                   JumpType::BREAK,
                   JumpType::CONTINUE,
                   JumpType::RETURN>()
        .visit(macro.block);
  }
  void visit(Probe &p)
  {
    JumpDisallowed<"probe", JumpType::BREAK, JumpType::CONTINUE>().visit(
        p.block);
  }
  void visit(Jump &jump)
  {
    if (((jump.ident == Ts) || ...))
      jump.addError() << "'" << opstr(jump) << "' "
                      << "statement is not allowed in a " << name.str();
  }
};

template <JumpType... Ts>
class ControlFlowAnalyser : public Visitor<ControlFlowAnalyser<Ts...>, bool> {
public:
  ControlFlowAnalyser(ASTContext &ast) : ast_(ast) {};

  // Returns true if the visited node terminates in a jump of type Ts..., that
  // applies to the scope of the first visit.
  using Visitor<ControlFlowAnalyser, bool>::visit;
  bool visit(Jump &jump)
  {
    return ((jump.ident == Ts) || ...);
  }
  bool visit(IfExpr &if_expr)
  {
    return visit(if_expr.cond) || (visit(if_expr.left) && visit(if_expr.right));
  }
  bool visit(Binop &binop)
  {
    return visit(binop.left) || visit(binop.right);
  }
  bool visit(ArrayAccess &acc)
  {
    return visit(acc.expr) || visit(acc.indexpr);
  }
  bool visit(AssignMapStatement &map_assign)
  {
    return visit(map_assign.key) || visit(map_assign.expr);
  }
  bool visit(BlockExpr &block)
  {
    for (size_t i = 0; i < block.stmts.size(); i++) {
      if (visit(block.stmts[i])) {
        StatementList dead_code;
        if (i + 1 < block.stmts.size()) {
          // Leave a warning on the first unreachable statement. All unreachable
          // statements are moved into a dead code block so that they can be
          // used for type inference, but this block will likely be folded away.
          block.stmts[i + 1].node().addWarning() << "Unreachable statement.";
          for (size_t j = i + 1; j < block.stmts.size(); j++) {
            dead_code.emplace_back(block.stmts[j]);
          }
          block.stmts.resize(i + 1);
        }
        if (!block.expr.is<None>()) {
          // If there is a non-none expression, then it is not possible
          // to evaluate this expression. This is also an error.
          block.expr.node().addWarning()
              << "Unreachable expression; block type is implicitly none.";
          // Since the expression is unreachable it just becomes another
          // statement in the dead code list, and not the block value.
          dead_code.emplace_back(
              ast_.make_node<ExprStatement>(block.expr.node().loc, block.expr));
          block.expr = ast_.make_node<None>(block.stmts[i].node().loc);
        }
        if (!dead_code.empty()) {
          // We rewrite the terminating statement to include the dead code in
          // an empty branch. This is because we need to put it somewhere so
          // that it can still be used for type inference, but it can't appear
          // after a block terminator. So we stuff it into a if that contains
          // the statements and isn't marked comptime.
          //
          // For example, the following block:
          // {
          //   return;
          //   foo()
          // }
          //
          // Becomes:
          // {
          //   if (true) {
          //     return;
          //   } else {
          //     foo();
          //   }
          // }
          auto original_ret = block.stmts[i];
          auto original_loc = original_ret.node().loc;
          block.stmts.resize(i);
          auto *cond = ast_.make_node<Boolean>(original_loc, true);
          auto *ret_block = ast_.make_node<BlockExpr>(
              original_loc,
              StatementList({ original_ret }),
              ast_.make_node<None>(original_loc));
          auto *dead_block = ast_.make_node<BlockExpr>(original_loc,
                                                       std::move(dead_code),
                                                       ast_.make_node<None>(
                                                           original_loc));
          auto *if_expr = ast_.make_node<IfExpr>(
              original_loc, cond, ret_block, dead_block);
          auto *if_stmt = ast_.make_node<ExprStatement>(original_loc, if_expr);
          block.stmts.emplace_back(if_stmt);
          // The deadcode still needs to have both branches covered.
          return visit(if_stmt);
        }
        return true;
      }
    }
    return visit(block.expr);
  }
  bool visit([[maybe_unused]] Subprog &subprog)
  {
    // In case we ever allow nested subprograms, these are explicitly
    // scope-limited, so neither jump affects overall control flow.
    return false;
  }
  bool visit(Unroll &unroll)
  {
    return visit(unroll.expr) || visit(unroll.block);
  }
  bool viist(Range &range)
  {
    return visit(range.start) || visit(range.end);
  }
  bool visit([[maybe_unused]] For &f)
  {
    // For loops will always terminate, all control flow statements within
    // the context of the loop apply only to the loop.... except the iterable
    // itself, which may be a block-expression range.
    return visit(f.iterable);
  }
  bool visit([[maybe_unused]] While &w)
  {
    // While loops will *not* always terminate, it is possible to construct
    // something that looks like this:
    //
    // while (true) {
    //   if (true) {
    //     return;
    //   }
    // }
    if constexpr ((... || (Ts == JumpType::RETURN))) {
      return visit(w.cond) ||
             ControlFlowAnalyser<JumpType::RETURN>(ast_).visit(w.block);
    } else {
      return visit(w.cond);
    }
  }

private:
  ASTContext &ast_;
};

class ControlFlowInjector : public Visitor<ControlFlowInjector> {
public:
  explicit ControlFlowInjector(ASTContext &ast) : ast_(ast) {};

  using Visitor<ControlFlowInjector>::visit;
  void visit(Subprog &subprog);
  void visit(Probe &probe);
  void visit(Macro &macro);
  void visit(For &f);
  void visit(While &w);

private:
  ASTContext &ast_;
};

} // namespace

template <JumpType T, JumpType... Ts>
void inject_jump(ASTContext &ast, Expression &expr)
{
  if (auto *blockexpr = expr.as<BlockExpr>()) {
    inject_jump<T, Ts...>(ast, *blockexpr);
  } else if (auto *if_expr = expr.as<IfExpr>()) {
    // Because ifs may be folded in the future, we need to inject into both in
    // the case that one of the branches has the terminator. It is also
    // possible that one of the branches also has it, so we don't inject there.
    ControlFlowAnalyser<T, Ts...> checker(ast);
    if (!checker.visit(if_expr->left)) {
      inject_jump<T, Ts...>(ast, if_expr->left);
    }
    if (!checker.visit(if_expr->right)) {
      inject_jump<T, Ts...>(ast, if_expr->right);
    }
  } else {
    // If we don't need to inject into an existing block, or a partial branch,
    // then we can inject a jump simply by converting to a block expression.
    auto *stmt = ast.make_node<ExprStatement>(expr.node().loc, expr);
    auto *ret = ast.make_node<Jump>(expr.node().loc, T);
    auto *none = ast.make_node<None>(expr.node().loc);
    auto *block = ast.make_node<BlockExpr>(expr.node().loc,
                                           StatementList({ stmt, ret }),
                                           none);
    expr.value = block;
  }
}

template <JumpType T, JumpType... Ts>
void inject_jump(ASTContext &ast, BlockExpr &block)
{
  if (block.expr.is<None>()) {
    // Check the final statement. If this statement is itself a block or if
    // expression, then we recursively inject a jump into that block.  This is
    // done before those branches may be pruned so we might end up with a
    // `return; return;` in that case.
    if (!block.stmts.empty() && block.stmts.back().is<ExprStatement>()) {
      inject_jump<T, Ts...>(ast, block.stmts.back().as<ExprStatement>()->expr);
    } else {
      auto *jump = ast.make_node<Jump>(block.loc, T);
      block.stmts.emplace_back(jump);
    }
  } else {
    inject_jump<T, Ts...>(ast, block.expr);
  }
}

void ExitReturn::visit(Expression &expr)
{
  Visitor<ExitReturn>::visit(expr);

  // The `exit` call is special and always carries an implicit return following
  // the call. We inject it automatically. Anything following this will be
  // labelled as unreachable as per the regular error paths below.
  //
  // This also prevents `exit` from appearing anywhere that a naked return is
  // not allowed (e.g. a macro, etc.) which is a useful feature.
  if (auto *call = expr.as<Call>()) {
    if (call->func == "exit" && call->vargs.size() <= 1) {
      inject_jump<JumpType::RETURN>(ast_, expr);
    }
  }
}

void ControlFlowInjector::visit(Subprog &subprog)
{
  bool has_return = ControlFlowAnalyser<JumpType::RETURN>(ast_).visit(
      subprog.block);
  if (!has_return) {
    if (subprog.return_type->type().IsVoidTy()) {
      inject_jump<JumpType::RETURN>(ast_, *subprog.block);
    } else {
      subprog.addError() << "Not all code paths returned a value";
    }
  }

  // Recurse to check loops, etc.
  visit(subprog.block);
}

void ControlFlowInjector::visit(Probe &probe)
{
  // Ensure that we have an implicit return for the probe.
  if (!ControlFlowAnalyser<JumpType::RETURN>(ast_).visit(probe.block)) {
    inject_jump<JumpType::RETURN>(ast_, *probe.block);
  }

  // Check all loops, etc.
  visit(probe.block);
}

void ControlFlowInjector::visit(Macro &macro)
{
  // Macros are already verified not to contain any control flow directly, but
  // may contain embedded loops, etc. These need to be fixed up to ensure that
  // every block ends with a control flow statement.
  visit(macro.block);
}

void ControlFlowInjector::visit(For &f)
{
  // Visit the loop and record any errors wherein we have
  // unreachable statements due to a unilateral break/continue.
  if (!ControlFlowAnalyser<JumpType::CONTINUE, JumpType::BREAK>(ast_).visit(
          f.block)) {
    inject_jump<JumpType::CONTINUE, JumpType::BREAK>(ast_, *f.block);
  }

  // Recurse to check nested loops, etc.
  visit(f.block);
}

void ControlFlowInjector::visit(While &w)
{
  // Same as for loops.
  if (!ControlFlowAnalyser<JumpType::CONTINUE,
                           JumpType::BREAK,
                           JumpType::RETURN>(ast_)
           .visit(w.block)) {
    inject_jump<JumpType::CONTINUE, JumpType::BREAK, JumpType::RETURN>(
        ast_, *w.block);
  }

  visit(w.block);
}

Pass CreateControlFlowPass()
{
  auto fn = [](ASTContext &ast) {
    ExitReturn(ast).visit(ast.root);
    JumpDisallowed<"program">().visit(ast.root);
    ControlFlowInjector r(ast);
    r.visit(ast.root);
    return ControlFlowChecked();
  };

  return Pass::create("ControlFlow", fn);
}

} // namespace bpftrace::ast
