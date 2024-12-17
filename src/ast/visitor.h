#pragma once

#include <string>

#include "ast/ast.h"

namespace bpftrace {
namespace ast {

/**
   Visitor for fully-static visitation

   This uses CRTP to make all calls static, while still allowing the basic
   entrypoint for a single visitor to be dispatched dynamically.
*/
template <typename Impl, typename R = void>
class Visitor {
public:
  R visit(Integer &integer __attribute__((__unused__)))
  {
    return _def();
  }
  R visit(PositionalParameter &integer __attribute__((__unused__)))
  {
    return _def();
  }
  R visit(String &string __attribute__((__unused__)))
  {
    return _def();
  }
  R visit(Builtin &builtin __attribute__((__unused__)))
  {
    return _def();
  }
  R visit(Identifier &identifier __attribute__((__unused__)))
  {
    return _def();
  }
  R visit(StackMode &mode __attribute__((__unused__)))
  {
    return _def();
  }
  R visit(Variable &var __attribute__((__unused__)))
  {
    return _def();
  }
  R visit(SubprogArg &subprog_arg __attribute__((__unused__)))
  {
    return _def();
  }
  R visit(AttachPoint &ap __attribute__((__unused__)))
  {
    return _def();
  }

  R visit(Call &call)
  {
    return _visit(call.vargs);
  }
  R visit(Sizeof &szof)
  {
    return _visit(szof.expr);
  }
  R visit(Offsetof &ofof)
  {
    return _visit(ofof.expr);
  }
  R visit(Map &map)
  {
    return _visit(map.key_expr);
  }
  R visit(Binop &binop)
  {
    _visit(binop.left);
    _visit(binop.right);
    return _def();
  }
  R visit(Unop &unop)
  {
    return _visit(unop.expr);
  }
  R visit(Ternary &ternary)
  {
    _visit(ternary.cond);
    _visit(ternary.left);
    _visit(ternary.right);
    return _def();
  }
  R visit(FieldAccess &acc)
  {
    return _visit(acc.expr);
  }
  R visit(ArrayAccess &arr)
  {
    _visit(arr.expr);
    _visit(arr.indexpr);
    return _def();
  }
  R visit(Cast &cast)
  {
    return _visit(cast.expr);
  }
  R visit(Tuple &tuple)
  {
    return _visit(tuple.elems);
  }
  R visit(ExprStatement &expr)
  {
    return _visit(expr.expr);
  }
  R visit(AssignMapStatement &assignment)
  {
    _visit(assignment.map);
    _visit(assignment.expr);
    return _def();
  }
  R visit(AssignVarStatement &assignment)
  {
    _visit(assignment.var);
    _visit(assignment.expr);
    return _def();
  }
  R visit(AssignConfigVarStatement &assignment)
  {
    return _visit(assignment.expr);
  }
  R visit(VarDeclStatement &decl)
  {
    return _visit(decl.var);
  }
  R visit(If &if_node)
  {
    _visit(if_node.cond);
    _visit(if_node.if_block);
    _visit(if_node.else_block);
    return _def();
  }
  R visit(Jump &jump)
  {
    return _visit(jump.return_value);
  }
  R visit(Unroll &unroll)
  {
    _visit(unroll.expr);
    _visit(unroll.block);
    return _def();
  }
  R visit(While &while_block)
  {
    _visit(while_block.cond);
    _visit(while_block.block);
    return _def();
  }
  R visit(For &for_loop)
  {
    _visit(for_loop.decl);
    _visit(for_loop.expr);
    _visit(for_loop.stmts);
    return _def();
  }
  R visit(Predicate &pred)
  {
    return _visit(pred.expr);
  }
  R visit(Probe &probe)
  {
    _visit(probe.attach_points);
    _visit(probe.pred);
    _visit(probe.block);
    return _def();
  }
  R visit(Config &config)
  {
    _visit(config.stmts);
    return _def();
  }
  R visit(Block &block)
  {
    _visit(block.stmts);
    return _def();
  }
  R visit(Subprog &subprog)
  {
    _visit(subprog.args);
    _visit(subprog.stmts);
    return _def();
  }
  R visit(Program &program)
  {
    _visit(program.functions);
    _visit(program.probes);
    _visit(program.config);
    return _def();
  }
  R visitAll(Program &program)
  {
    return _visit(program);
  }

  // This can be used to provide visit behavior for each node in the program.
  // This will be always invoked as a special case, and therefore cannot affect
  // the control flow of the walk.
  void preVisit([[maybe_unused]] Node &node)
  {
  }

  // Automatically unpacked and dispatch all variant and vector types into the
  // suitable visitor method, which includes statements and statement lists.
  // These may be override by subtype explicitly as well.
  template <typename... Ts>
  R visit(std::variant<Ts *...> var)
  {
    return std::visit([this](const auto value) -> R { return _visit(*value); },
                      var);
  }
  template <typename T>
  R visit(const std::vector<T> &var)
  {
    for (const auto &value : var) {
      _visit(value);
    }
    return _def();
  }
  template <typename T>
  R visit(std::optional<T> &var)
  {
    if (var)
      return _visit(*var);
    return _def();
  }
  template <typename T>
  R visit(T *ptr)
  {
    if (ptr)
      return _visit(*ptr);
    return _def();
  }

  // There are the runtime-type adaptors that are currently required for
  // Expression and Statement, but can be removed by encoding this type
  // information into the AST directly.
  template <typename T, typename... Ts>
  R tryVisit(Node *node)
  {
    if (auto *t = dynamic_cast<T>(node))
      return _visit(*t);
    if constexpr (sizeof...(Ts) != 0) {
      return tryVisit<Ts...>(node);
    }
    return _def();
  }
  R visit(Expression &expr)
  {
    return tryVisit<Integer *,
                    PositionalParameter *,
                    String *,
                    StackMode *,
                    Identifier *,
                    Builtin *,
                    Call *,
                    Sizeof *,
                    Offsetof *,
                    Map *,
                    Variable *,
                    Binop *,
                    Unop *,
                    FieldAccess *,
                    ArrayAccess *,
                    Cast *,
                    Tuple *,
                    Ternary *>(&expr);
  }
  R visit(Statement &stmt)
  {
    return tryVisit<ExprStatement *,
                    VarDeclStatement *,
                    AssignMapStatement *,
                    AssignVarStatement *,
                    AssignConfigVarStatement *,
                    Block *,
                    If *,
                    Unroll *,
                    Jump *,
                    While *,
                    For *,
                    Config *>(&stmt);
  }

  // This is the entrypoint that should be called from the pass itself. It
  // ensures that it calls the appropriate hooks before walking.
  R run(Program &program)
  {
    return _visit(program);
  }

private:
  template <typename T>
  R _visit(T &t)
  {
    // Before dispatching to the specific visit method, we invoke the walk hook
    // which can be used to enumerate nodes, dump nodes, etc.
    Impl *impl = static_cast<Impl *>(this);
    if constexpr (std::is_base_of_v<Node, T>) {
      Node *node = static_cast<Node *>(&t);
      impl->preVisit(*node);
    }
    return impl->visit(t);
  }
  R _def()
  {
    if constexpr (!std::is_void<R>::value) {
      return R();
    }
  }
};

} // namespace ast
} // namespace bpftrace
