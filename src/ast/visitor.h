#pragma once

#include <optional>
#include <variant>

#include "ast/ast.h"
#include "ast/context.h"

namespace bpftrace::ast {

// Visitor for fully-static visitation.
//
// This uses CRTP to make all calls static, while still allowing the entrypoint
// for a single visitor to be dispatched dynamically. The implementation may
// optionally provide individual `visit` methods. To replace specific types,
// a `visit` method must be provided on the suitable dynamic type (e.g. you
// may want `Expression` or `Statement`).
template <typename Impl, typename R = void>
class Visitor {
public:
  // visit methods are used to traverse the graph, and are provided a reference
  // to the underlying node. The visit is invoked *before* the replace call,
  // and can directly consume and modify the results of the visit.
  R visit([[maybe_unused]] Integer &integer)
  {
    return default_value();
  }
  R visit([[maybe_unused]] NegativeInteger &integer)
  {
    return default_value();
  }
  R visit([[maybe_unused]] Boolean &boolean)
  {
    return default_value();
  }
  R visit([[maybe_unused]] PositionalParameter &param)
  {
    return default_value();
  }
  R visit([[maybe_unused]] PositionalParameterCount &param)
  {
    return default_value();
  }
  R visit([[maybe_unused]] String &string)
  {
    return default_value();
  }
  R visit([[maybe_unused]] None &none)
  {
    return default_value();
  }
  R visit([[maybe_unused]] Builtin &builtin)
  {
    return default_value();
  }
  R visit([[maybe_unused]] Identifier &identifier)
  {
    return default_value();
  }
  R visit([[maybe_unused]] Variable &var)
  {
    return default_value();
  }
  R visit([[maybe_unused]] VariableAddr &var_addr)
  {
    return visitImpl(var_addr.var);
  }
  R visit(SubprogArg &subprog_arg)
  {
    visitImpl(subprog_arg.var);
    visitImpl(subprog_arg.typeof);
    return default_value();
  }
  R visit([[maybe_unused]] AttachPoint &ap)
  {
    return default_value();
  }
  R visit(Call &call)
  {
    return visitImpl(call.vargs);
  }
  R visit(Sizeof &szof)
  {
    return visitImpl(szof.record);
  }
  R visit(Offsetof &ofof)
  {
    return visitImpl(ofof.record);
  }
  R visit(Typeof &typeof)
  {
    return visitImpl(typeof.record);
  }
  R visit(Typeinfo &typeinfo)
  {
    return visitImpl(typeinfo.typeof);
  }
  R visit(Comptime &comptime)
  {
    return visitImpl(comptime.expr);
  }
  R visit([[maybe_unused]] MapDeclStatement &decl)
  {
    // This isn't a regular expression, and therefore the call
    // will not be visited unless specifically overrden.
    return default_value();
  }
  R visit([[maybe_unused]] Map &map)
  {
    return default_value();
  }
  R visit([[maybe_unused]] MapAddr &map_addr)
  {
    return visitImpl(map_addr.map);
  }
  R visit(Binop &binop)
  {
    visitImpl(binop.left);
    visitImpl(binop.right);
    return default_value();
  }
  R visit(Unop &unop)
  {
    return visitImpl(unop.expr);
  }
  R visit(IfExpr &if_expr)
  {
    visitImpl(if_expr.cond);
    visitImpl(if_expr.left);
    visitImpl(if_expr.right);
    return default_value();
  }
  R visit(FieldAccess &acc)
  {
    return visitImpl(acc.expr);
  }
  R visit(ArrayAccess &arr)
  {
    visitImpl(arr.indexpr);
    return visitImpl(arr.expr);
  }
  R visit(TupleAccess &acc)
  {
    return visitImpl(acc.expr);
  }
  R visit(MapAccess &acc)
  {
    visitImpl(acc.map);
    return visitImpl(acc.key);
  }
  R visit(Cast &cast)
  {
    visitImpl(cast.typeof);
    return visitImpl(cast.expr);
  }
  R visit(Tuple &tuple)
  {
    return visitImpl(tuple.elems);
  }
  R visit(NamedArgument &named_arg)
  {
    return visitImpl(named_arg.expr);
  }
  R visit(Record &record)
  {
    return visitImpl(record.elems);
  }
  R visit(ExprStatement &expr)
  {
    return visitImpl(expr.expr);
  }
  R visit(AssignScalarMapStatement &assignment)
  {
    visitImpl(assignment.map);
    return visitImpl(assignment.expr);
  }
  R visit(AssignMapStatement &assignment)
  {
    visitImpl(assignment.map_access);
    return visitImpl(assignment.expr);
  }
  R visit(AssignVarStatement &assignment)
  {
    visitImpl(assignment.var_decl);
    return visitImpl(assignment.expr);
  }
  R visit([[maybe_unused]] AssignConfigVarStatement &assignment)
  {
    return default_value();
  }
  R visit(VarDeclStatement &decl)
  {
    visitImpl(decl.var);
    visitImpl(decl.typeof);
    return default_value();
  }
  R visit(DiscardExpr &discard_expr)
  {
    return visitImpl(discard_expr.expr);
  }
  R visit(Jump &jump)
  {
    return visitImpl(jump.return_value);
  }
  R visit(Unroll &unroll)
  {
    visitImpl(unroll.expr);
    visitImpl(unroll.block);
    return default_value();
  }
  R visit(While &while_block)
  {
    visitImpl(while_block.cond);
    visitImpl(while_block.block);
    return default_value();
  }
  R visit(Range &range)
  {
    visitImpl(range.start);
    visitImpl(range.end);
    return default_value();
  }
  R visit(For &for_loop)
  {
    visitImpl(for_loop.decl);
    visitImpl(for_loop.iterable);
    visitImpl(for_loop.block);
    return default_value();
  }
  R visit(Probe &probe)
  {
    visitImpl(probe.attach_points);
    return visitImpl(probe.block);
  }
  R visit(Config &config)
  {
    visitImpl(config.stmts);
    return default_value();
  }
  R visit(BlockExpr &block)
  {
    visitImpl(block.stmts);
    return visitImpl(block.expr);
  }
  R visit([[maybe_unused]] Macro &macro)
  {
    // In general because macros are expanded in an early pass (macro_expansion)
    // later passes shouldn't visit any macros; visitation should be specially
    // handled by the macro_expansion pass.
    return default_value();
  }
  R visit(Subprog &subprog)
  {
    visitImpl(subprog.args);
    visitImpl(subprog.return_type);
    return visitImpl(subprog.block);
  }
  R visit([[maybe_unused]] RootImport &imp)
  {
    return default_value();
  }
  R visit([[maybe_unused]] StatementImport &imp)
  {
    return default_value();
  }
  R visit(Program &program)
  {
    // This order is important.
    visitImpl(program.c_statements);
    visitImpl(program.config);
    visitImpl(program.imports);
    visitImpl(program.macros);
    visitImpl(program.functions);
    visitImpl(program.map_decls);
    visitImpl(program.probes);
    return default_value();
  }
  R visit(Iterable &iterable)
  {
    return visitImpl(iterable.value);
  }
  R visit(Expression &expr)
  {
    return visitImpl(expr.value);
  }
  R visit(Statement &stmt)
  {
    return visitImpl(stmt.value);
  }
  R visit(RootStatement &root)
  {
    return visitImpl(root.value);
  }
  R visit([[maybe_unused]] CStatement &cstmt)
  {
    return default_value();
  }
  R visit([[maybe_unused]] const SizedType &type)
  {
    return default_value();
  }

  // Automatically unpack and dispatch all variant and vector types into the
  // suitable visitor method.
  //
  // In order to automatically replace a variant, e.g. change from type A to
  // type B, it is necessary to provide a replace method that accepts that
  // variant type directly. This could still dispatch via the standard visit
  // function, which could e.g. return the replacement pointer, but this would
  // be a single specialized pass for this case.
  template <typename... Ts>
  R visit(std::variant<Ts...> &var)
  {
    return std::visit([&](auto &v) -> R { return visitImpl(v); }, var);
  }
  template <typename T>
  R visit(std::vector<T> &var)
  {
    for (auto &value : var) {
      visitImpl(value);
    }
    return default_value();
  }
  template <typename T>
  R visit(std::optional<T> &var)
  {
    if (var.has_value()) {
      return visitImpl(var.value());
    }
    return default_value();
  }
  template <typename T>
  R visit(T *ptr)
  {
    if (ptr)
      return visitImpl(*ptr);
    return default_value();
  }

private:
  template <typename T>
  R visitImpl(T &t)
  {
    Impl *impl = static_cast<Impl *>(this);
    return impl->visit(t);
  }
  R default_value()
  {
    if constexpr (!std::is_void_v<R>) {
      return R();
    }
  }
};

} // namespace bpftrace::ast
