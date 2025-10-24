#include <compare>
#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include "ast/ast.h"
#include "ast/clone.h"
#include "ast/context.h"
#include "ast/location.h"
#include "types.h"

namespace bpftrace::test::ast {

using namespace bpftrace::ast;

template <typename T>
std::vector<T *> variants(ASTContext &c, SourceLocation l);

template <typename T>
  requires(std::is_same_v<T, Expression> || std::is_same_v<T, Statement> ||
           std::is_same_v<T, Iterable> || std::is_same_v<T, RootStatement>)
std::vector<T> variants(ASTContext &c, SourceLocation l);

template <>
std::vector<Integer *> variants<Integer>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Integer>(l, 42UL),
           c.make_node<Integer>(l, 24UL),
           c.make_node<Integer>(l, 100UL),
           c.make_node<Integer>(l, 0UL) };
}

template <>
std::vector<NegativeInteger *> variants<NegativeInteger>(ASTContext &c,
                                                         SourceLocation l)
{
  return { c.make_node<NegativeInteger>(l, -42L),
           c.make_node<NegativeInteger>(l, -24L),
           c.make_node<NegativeInteger>(l, -100L),
           c.make_node<NegativeInteger>(l, -1L) };
}

template <>
std::vector<Boolean *> variants<Boolean>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Boolean>(l, true), c.make_node<Boolean>(l, false) };
}

template <>
std::vector<String *> variants<String>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<String>(l, std::string("test")),
           c.make_node<String>(l, std::string("different")),
           c.make_node<String>(l, std::string("another")),
           c.make_node<String>(l, std::string("")) };
}

template <>
std::vector<None *> variants<None>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<None>(l) };
}

template <>
std::vector<Identifier *> variants<Identifier>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Identifier>(l, std::string("var")),
           c.make_node<Identifier>(l, std::string("other")),
           c.make_node<Identifier>(l, std::string("xyz")),
           c.make_node<Identifier>(l, std::string("_test")) };
}

template <>
std::vector<Builtin *> variants<Builtin>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Builtin>(l, std::string("pid")),
           c.make_node<Builtin>(l, std::string("tid")),
           c.make_node<Builtin>(l, std::string("uid")),
           c.make_node<Builtin>(l, std::string("comm")) };
}

template <>
std::vector<Variable *> variants<Variable>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Variable>(l, std::string("$var")),
           c.make_node<Variable>(l, std::string("$other")),
           c.make_node<Variable>(l, std::string("$x")),
           c.make_node<Variable>(l, std::string("$test123")) };
}

template <>
std::vector<Map *> variants<Map>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Map>(l, std::string("@map")),
           c.make_node<Map>(l, std::string("@other")),
           c.make_node<Map>(l, std::string("@data")),
           c.make_node<Map>(l, std::string("@count")) };
}

template <>
std::vector<PositionalParameter *> variants<PositionalParameter>(
    ASTContext &c,
    SourceLocation l)
{
  return { c.make_node<PositionalParameter>(l, 1L),
           c.make_node<PositionalParameter>(l, 2L),
           c.make_node<PositionalParameter>(l, 0L),
           c.make_node<PositionalParameter>(l, 10L) };
}

template <>
std::vector<PositionalParameterCount *> variants<PositionalParameterCount>(
    ASTContext &c,
    SourceLocation l)
{
  return { c.make_node<PositionalParameterCount>(l) };
}

template <>
std::vector<Call *> variants<Call>(ASTContext &c, SourceLocation l)
{
  ExpressionList args1;
  args1.emplace_back(c.make_node<Integer>(l, 1UL));

  ExpressionList args2;
  args2.emplace_back(c.make_node<String>(l, std::string("test")));

  ExpressionList args3;
  args3.emplace_back(c.make_node<Integer>(l, 2UL));
  args3.emplace_back(c.make_node<String>(l, std::string("arg")));

  ExpressionList args4;

  return { c.make_node<Call>(l, std::string("printf"), std::move(args1)),
           c.make_node<Call>(l, std::string("count"), std::move(args4)),
           c.make_node<Call>(l, std::string("printf"), std::move(args2)),
           c.make_node<Call>(l, std::string("printf"), std::move(args3)) };
}

template <>
std::vector<Sizeof *> variants<Sizeof>(ASTContext &c, SourceLocation l)
{
  Expression expr = c.make_node<Integer>(l, 42UL);
  return { c.make_node<Sizeof>(l, CreateInt32()),
           c.make_node<Sizeof>(l, CreateInt64()),
           c.make_node<Sizeof>(l, CreateUInt32()),
           c.make_node<Sizeof>(l, std::move(expr)) };
}

template <>
std::vector<Offsetof *> variants<Offsetof>(ASTContext &c, SourceLocation l)
{
  std::vector<std::string> field1 = { "field" };
  std::vector<std::string> field2 = { "other" };
  std::vector<std::string> field3 = { "field", "nested" };
  Expression expr = c.make_node<Variable>(l, std::string("$var"));
  std::vector<std::string> field4 = { "member" };

  return { c.make_node<Offsetof>(l, CreateInteger(32, false), field1),
           c.make_node<Offsetof>(l, CreateInteger(64, false), field2),
           c.make_node<Offsetof>(l, CreateString(64), field3),
           c.make_node<Offsetof>(l, std::move(expr), field4) };
}

template <>
std::vector<VariableAddr *> variants<VariableAddr>(ASTContext &c,
                                                   SourceLocation l)
{
  auto *var1 = c.make_node<Variable>(l, std::string("$var"));
  auto *var2 = c.make_node<Variable>(l, std::string("$other"));
  auto *var3 = c.make_node<Variable>(l, std::string("$x"));

  return { c.make_node<VariableAddr>(l, var1),
           c.make_node<VariableAddr>(l, var2),
           c.make_node<VariableAddr>(l, var3) };
}

template <>
std::vector<MapAddr *> variants<MapAddr>(ASTContext &c, SourceLocation l)
{
  auto *map1 = c.make_node<Map>(l, std::string("@map"));
  auto *map2 = c.make_node<Map>(l, std::string("@other"));
  auto *map3 = c.make_node<Map>(l, std::string("@data"));

  return { c.make_node<MapAddr>(l, map1),
           c.make_node<MapAddr>(l, map2),
           c.make_node<MapAddr>(l, map3) };
}

template <>
std::vector<Binop *> variants<Binop>(ASTContext &c, SourceLocation l)
{
  Expression left1 = c.make_node<Integer>(l, 1UL);
  Expression right1 = c.make_node<Integer>(l, 2UL);

  Expression left2 = c.make_node<Integer>(l, 3UL);
  Expression right2 = c.make_node<Integer>(l, 4UL);

  Expression left3 = c.make_node<Integer>(l, 1UL);
  Expression right3 = c.make_node<Integer>(l, 2UL);

  Expression left4 = c.make_node<Variable>(l, std::string("$x"));
  Expression right4 = c.make_node<Integer>(l, 5UL);

  return {
    c.make_node<Binop>(l, std::move(left1), Operator::PLUS, std::move(right1)),
    c.make_node<Binop>(l, std::move(left2), Operator::MINUS, std::move(right2)),
    c.make_node<Binop>(l, std::move(left3), Operator::MUL, std::move(right3)),
    c.make_node<Binop>(l, std::move(left4), Operator::PLUS, std::move(right4))
  };
}

template <>
std::vector<Unop *> variants<Unop>(ASTContext &c, SourceLocation l)
{
  Expression expr1 = c.make_node<Integer>(l, 42UL);
  Expression expr2 = c.make_node<Integer>(l, 24UL);
  Expression expr3 = c.make_node<Variable>(l, std::string("$x"));

  return { c.make_node<Unop>(l, std::move(expr1), Operator::LNOT),
           c.make_node<Unop>(l, std::move(expr2), Operator::BNOT),
           c.make_node<Unop>(l, std::move(expr3), Operator::LNOT) };
}

template <>
std::vector<FieldAccess *> variants<FieldAccess>(ASTContext &c,
                                                 SourceLocation l)
{
  Expression expr1 = c.make_node<Variable>(l, std::string("$var"));
  Expression expr2 = c.make_node<Variable>(l, std::string("$other"));
  Expression expr3 = c.make_node<Variable>(l, std::string("$var"));
  Expression expr4 = c.make_node<Builtin>(l, std::string("pid"));

  return {
    c.make_node<FieldAccess>(l, std::move(expr1), std::string("field")),
    c.make_node<FieldAccess>(l, std::move(expr2), std::string("field")),
    c.make_node<FieldAccess>(l, std::move(expr3), std::string("other")),
    c.make_node<FieldAccess>(l, std::move(expr4), std::string("member"))
  };
}

template <>
std::vector<ArrayAccess *> variants<ArrayAccess>(ASTContext &c,
                                                 SourceLocation l)
{
  Expression expr1 = c.make_node<Variable>(l, std::string("$arr"));
  Expression index1 = c.make_node<Integer>(l, 0UL);

  Expression expr2 = c.make_node<Variable>(l, std::string("$other"));
  Expression index2 = c.make_node<Integer>(l, 1UL);

  Expression expr3 = c.make_node<Variable>(l, std::string("$arr"));
  Expression index3 = c.make_node<Integer>(l, 2UL);

  Expression expr4 = c.make_node<Map>(l, std::string("@data"));
  Expression index4 = c.make_node<Variable>(l, std::string("$key"));

  return { c.make_node<ArrayAccess>(l, std::move(expr1), std::move(index1)),
           c.make_node<ArrayAccess>(l, std::move(expr2), std::move(index2)),
           c.make_node<ArrayAccess>(l, std::move(expr3), std::move(index3)),
           c.make_node<ArrayAccess>(l, std::move(expr4), std::move(index4)) };
}

template <>
std::vector<TupleAccess *> variants<TupleAccess>(ASTContext &c,
                                                 SourceLocation l)
{
  Expression expr1 = c.make_node<Variable>(l, std::string("$tuple"));
  Expression expr2 = c.make_node<Variable>(l, std::string("$other"));
  Expression expr3 = c.make_node<Variable>(l, std::string("$tuple"));
  Expression expr4 = c.make_node<Variable>(l, std::string("$xyz"));

  return { c.make_node<TupleAccess>(l, std::move(expr1), 0),
           c.make_node<TupleAccess>(l, std::move(expr2), 0),
           c.make_node<TupleAccess>(l, std::move(expr3), 1),
           c.make_node<TupleAccess>(l, std::move(expr4), 2) };
}

template <>
std::vector<MapAccess *> variants<MapAccess>(ASTContext &c, SourceLocation l)
{
  auto *map1 = c.make_node<Map>(l, std::string("@map"));
  Expression key1 = c.make_node<Integer>(l, 1UL);

  auto *map2 = c.make_node<Map>(l, std::string("@other"));
  Expression key2 = c.make_node<Integer>(l, 2UL);

  auto *map3 = c.make_node<Map>(l, std::string("@map"));
  Expression key3 = c.make_node<String>(l, std::string("key"));

  auto *map4 = c.make_node<Map>(l, std::string("@data"));
  Expression key4 = c.make_node<Variable>(l, std::string("$key"));

  return { c.make_node<MapAccess>(l, map1, std::move(key1)),
           c.make_node<MapAccess>(l, map2, std::move(key2)),
           c.make_node<MapAccess>(l, map3, std::move(key3)),
           c.make_node<MapAccess>(l, map4, std::move(key4)) };
}

template <>
std::vector<Cast *> variants<Cast>(ASTContext &c, SourceLocation l)
{
  auto *typeof1 = c.make_node<Typeof>(l, CreateInt32());
  Expression expr1 = c.make_node<Integer>(l, 42UL);

  auto *typeof2 = c.make_node<Typeof>(l, CreateInt64());
  Expression expr2 = c.make_node<Integer>(l, 24UL);

  auto *typeof3 = c.make_node<Typeof>(l, CreateInt32());
  Expression expr3 = c.make_node<Variable>(l, std::string("$x"));

  auto *typeof4 = c.make_node<Typeof>(l, CreateUInt32());
  Expression expr4 = c.make_node<Integer>(l, 42UL);

  return { c.make_node<Cast>(l, typeof1, std::move(expr1)),
           c.make_node<Cast>(l, typeof2, std::move(expr2)),
           c.make_node<Cast>(l, typeof3, std::move(expr3)),
           c.make_node<Cast>(l, typeof4, std::move(expr4)) };
}

template <>
std::vector<Tuple *> variants<Tuple>(ASTContext &c, SourceLocation l)
{
  ExpressionList elems1;
  elems1.emplace_back(c.make_node<Integer>(l, 1UL));
  elems1.emplace_back(c.make_node<Integer>(l, 2UL));

  ExpressionList elems2;
  elems2.emplace_back(c.make_node<Integer>(l, 3UL));
  elems2.emplace_back(c.make_node<Integer>(l, 4UL));

  ExpressionList elems3;
  elems3.emplace_back(c.make_node<String>(l, std::string("a")));
  elems3.emplace_back(c.make_node<String>(l, std::string("b")));

  ExpressionList elems4;
  elems4.emplace_back(c.make_node<Integer>(l, 1UL));
  elems4.emplace_back(c.make_node<String>(l, std::string("mixed")));
  elems4.emplace_back(c.make_node<Boolean>(l, true));

  return { c.make_node<Tuple>(l, std::move(elems1)),
           c.make_node<Tuple>(l, std::move(elems2)),
           c.make_node<Tuple>(l, std::move(elems3)),
           c.make_node<Tuple>(l, std::move(elems4)) };
}

template <>
std::vector<IfExpr *> variants<IfExpr>(ASTContext &c, SourceLocation l)
{
  Expression cond1 = c.make_node<Boolean>(l, true);
  Expression left1 = c.make_node<Integer>(l, 1UL);
  Expression right1 = c.make_node<Integer>(l, 2UL);

  Expression cond2 = c.make_node<Boolean>(l, false);
  Expression left2 = c.make_node<Integer>(l, 3UL);
  Expression right2 = c.make_node<Integer>(l, 4UL);

  Expression cond3 = c.make_node<Variable>(l, std::string("$flag"));
  Expression left3 = c.make_node<String>(l, std::string("yes"));
  Expression right3 = c.make_node<String>(l, std::string("no"));

  Expression cond4 = c.make_node<Boolean>(l, true);
  Expression left4 = c.make_node<Integer>(l, 10UL);
  Expression right4 = c.make_node<Integer>(l, 20UL);

  return { c.make_node<IfExpr>(
               l, std::move(cond1), std::move(left1), std::move(right1)),
           c.make_node<IfExpr>(
               l, std::move(cond2), std::move(left2), std::move(right2)),
           c.make_node<IfExpr>(
               l, std::move(cond3), std::move(left3), std::move(right3)),
           c.make_node<IfExpr>(
               l, std::move(cond4), std::move(left4), std::move(right4)) };
}

template <>
std::vector<BlockExpr *> variants<BlockExpr>(ASTContext &c, SourceLocation l)
{
  StatementList stmts1;
  Expression expr1 = c.make_node<Integer>(l, 42UL);

  StatementList stmts2;
  Expression expr2 = c.make_node<Integer>(l, 24UL);

  StatementList stmts3;
  Expression stmt_expr = c.make_node<Variable>(l, std::string("$x"));
  stmts3.emplace_back(c.make_node<ExprStatement>(l, std::move(stmt_expr)));
  Expression expr3 = c.make_node<String>(l, std::string("result"));

  StatementList stmts4;
  Expression expr4 = c.make_node<Boolean>(l, true);

  return { c.make_node<BlockExpr>(l, std::move(stmts1), std::move(expr1)),
           c.make_node<BlockExpr>(l, std::move(stmts2), std::move(expr2)),
           c.make_node<BlockExpr>(l, std::move(stmts3), std::move(expr3)),
           c.make_node<BlockExpr>(l, std::move(stmts4), std::move(expr4)) };
}

template <>
std::vector<Typeinfo *> variants<Typeinfo>(ASTContext &c, SourceLocation l)
{
  auto *typeof1 = c.make_node<Typeof>(l, CreateInt32());
  auto *typeof2 = c.make_node<Typeof>(l, CreateInt64());
  auto *typeof3 = c.make_node<Typeof>(l, CreateUInt32());
  Expression expr = c.make_node<Variable>(l, std::string("$x"));
  auto *typeof4 = c.make_node<Typeof>(l, std::move(expr));

  return { c.make_node<Typeinfo>(l, typeof1),
           c.make_node<Typeinfo>(l, typeof2),
           c.make_node<Typeinfo>(l, typeof3),
           c.make_node<Typeinfo>(l, typeof4) };
}

template <>
std::vector<Comptime *> variants<Comptime>(ASTContext &c, SourceLocation l)
{
  Expression expr1 = c.make_node<Integer>(l, 42UL);
  Expression expr2 = c.make_node<Integer>(l, 24UL);
  Expression expr3 = c.make_node<String>(l, std::string("test"));
  Expression expr4 = c.make_node<Variable>(l, std::string("$x"));

  return { c.make_node<Comptime>(l, std::move(expr1)),
           c.make_node<Comptime>(l, std::move(expr2)),
           c.make_node<Comptime>(l, std::move(expr3)),
           c.make_node<Comptime>(l, std::move(expr4)) };
}

template <>
std::vector<ExprStatement *> variants<ExprStatement>(ASTContext &c,
                                                     SourceLocation l)
{
  Expression expr1 = c.make_node<Integer>(l, 42UL);
  Expression expr2 = c.make_node<Integer>(l, 24UL);
  Expression expr3 = c.make_node<String>(l, std::string("test"));
  Expression expr4 = c.make_node<Variable>(l, std::string("$x"));

  return { c.make_node<ExprStatement>(l, std::move(expr1)),
           c.make_node<ExprStatement>(l, std::move(expr2)),
           c.make_node<ExprStatement>(l, std::move(expr3)),
           c.make_node<ExprStatement>(l, std::move(expr4)) };
}

template <>
std::vector<VarDeclStatement *> variants<VarDeclStatement>(ASTContext &c,
                                                           SourceLocation l)
{
  auto *var1 = c.make_node<Variable>(l, std::string("$var"));
  auto *typeof1 = c.make_node<Typeof>(l, CreateInt32());

  auto *var2 = c.make_node<Variable>(l, std::string("$other"));
  auto *typeof2 = c.make_node<Typeof>(l, CreateInt64());

  auto *var3 = c.make_node<Variable>(l, std::string("$x"));
  auto *typeof3 = c.make_node<Typeof>(l, CreateUInt32());

  auto *var4 = c.make_node<Variable>(l, std::string("$test"));
  auto *typeof4 = c.make_node<Typeof>(l, CreateInt32());

  return { c.make_node<VarDeclStatement>(l, var1, typeof1),
           c.make_node<VarDeclStatement>(l, var2, typeof2),
           c.make_node<VarDeclStatement>(l, var3, typeof3),
           c.make_node<VarDeclStatement>(l, var4, typeof4) };
}

template <>
std::vector<AssignScalarMapStatement *> variants<AssignScalarMapStatement>(
    ASTContext &c,
    SourceLocation l)
{
  auto *map1 = c.make_node<Map>(l, std::string("@map"));
  Expression expr1 = c.make_node<Integer>(l, 42UL);

  auto *map2 = c.make_node<Map>(l, std::string("@other"));
  Expression expr2 = c.make_node<Integer>(l, 24UL);

  auto *map3 = c.make_node<Map>(l, std::string("@map"));
  Expression expr3 = c.make_node<String>(l, std::string("value"));

  auto *map4 = c.make_node<Map>(l, std::string("@data"));
  Expression expr4 = c.make_node<Variable>(l, std::string("$x"));

  return { c.make_node<AssignScalarMapStatement>(l, map1, std::move(expr1)),
           c.make_node<AssignScalarMapStatement>(l, map2, std::move(expr2)),
           c.make_node<AssignScalarMapStatement>(l, map3, std::move(expr3)),
           c.make_node<AssignScalarMapStatement>(l, map4, std::move(expr4)) };
}

template <>
std::vector<AssignMapStatement *> variants<AssignMapStatement>(ASTContext &c,
                                                               SourceLocation l)
{
  auto *map1 = c.make_node<Map>(l, std::string("@map"));
  Expression key1 = c.make_node<Integer>(l, 1UL);
  Expression expr1 = c.make_node<Integer>(l, 42UL);

  auto *map2 = c.make_node<Map>(l, std::string("@other"));
  Expression key2 = c.make_node<Integer>(l, 2UL);
  Expression expr2 = c.make_node<Integer>(l, 24UL);

  auto *map3 = c.make_node<Map>(l, std::string("@map"));
  Expression key3 = c.make_node<String>(l, std::string("key"));
  Expression expr3 = c.make_node<String>(l, std::string("value"));

  auto *map4 = c.make_node<Map>(l, std::string("@data"));
  Expression key4 = c.make_node<Variable>(l, std::string("$k"));
  Expression expr4 = c.make_node<Variable>(l, std::string("$v"));

  return {
    c.make_node<AssignMapStatement>(l, map1, std::move(key1), std::move(expr1)),
    c.make_node<AssignMapStatement>(l, map2, std::move(key2), std::move(expr2)),
    c.make_node<AssignMapStatement>(l, map3, std::move(key3), std::move(expr3)),
    c.make_node<AssignMapStatement>(l, map4, std::move(key4), std::move(expr4))
  };
}

template <>
std::vector<AssignVarStatement *> variants<AssignVarStatement>(ASTContext &c,
                                                               SourceLocation l)
{
  auto *var1 = c.make_node<Variable>(l, std::string("$var"));
  Expression expr1 = c.make_node<Integer>(l, 42UL);

  auto *var2 = c.make_node<Variable>(l, std::string("$other"));
  Expression expr2 = c.make_node<Integer>(l, 24UL);

  auto *var3 = c.make_node<Variable>(l, std::string("$var"));
  Expression expr3 = c.make_node<String>(l, std::string("value"));

  auto *var4 = c.make_node<Variable>(l, std::string("$x"));
  Expression expr4 = c.make_node<Boolean>(l, true);

  return { c.make_node<AssignVarStatement>(l, var1, std::move(expr1)),
           c.make_node<AssignVarStatement>(l, var2, std::move(expr2)),
           c.make_node<AssignVarStatement>(l, var3, std::move(expr3)),
           c.make_node<AssignVarStatement>(l, var4, std::move(expr4)) };
}

template <>
std::vector<Unroll *> variants<Unroll>(ASTContext &c, SourceLocation l)
{
  Expression expr1 = c.make_node<Integer>(l, 10UL);
  StatementList stmts1;
  Expression block_expr1 = c.make_node<Integer>(l, 1UL);
  auto *block1 = c.make_node<BlockExpr>(l,
                                        std::move(stmts1),
                                        std::move(block_expr1));

  Expression expr2 = c.make_node<Integer>(l, 5UL);
  StatementList stmts2;
  Expression block_expr2 = c.make_node<Integer>(l, 2UL);
  auto *block2 = c.make_node<BlockExpr>(l,
                                        std::move(stmts2),
                                        std::move(block_expr2));

  Expression expr3 = c.make_node<Variable>(l, std::string("$count"));
  StatementList stmts3;
  Expression block_expr3 = c.make_node<String>(l, std::string("loop"));
  auto *block3 = c.make_node<BlockExpr>(l,
                                        std::move(stmts3),
                                        std::move(block_expr3));

  Expression expr4 = c.make_node<Integer>(l, 10UL);
  StatementList stmts4;
  Expression block_expr4 = c.make_node<Integer>(l, 3UL);
  auto *block4 = c.make_node<BlockExpr>(l,
                                        std::move(stmts4),
                                        std::move(block_expr4));

  return { c.make_node<Unroll>(l, std::move(expr1), block1),
           c.make_node<Unroll>(l, std::move(expr2), block2),
           c.make_node<Unroll>(l, std::move(expr3), block3),
           c.make_node<Unroll>(l, std::move(expr4), block4) };
}

template <>
std::vector<Jump *> variants<Jump>(ASTContext &c, SourceLocation l)
{
  Expression return_val1 = c.make_node<Integer>(l, 42UL);
  Expression return_val2 = c.make_node<String>(l, std::string("done"));

  return { c.make_node<Jump>(l, JumpType::RETURN),
           c.make_node<Jump>(l, JumpType::CONTINUE),
           c.make_node<Jump>(l, JumpType::BREAK),
           c.make_node<Jump>(l, JumpType::RETURN, std::move(return_val1)),
           c.make_node<Jump>(l, JumpType::RETURN, std::move(return_val2)) };
}

template <>
std::vector<While *> variants<While>(ASTContext &c, SourceLocation l)
{
  Expression cond1 = c.make_node<Boolean>(l, true);
  StatementList stmts1;
  Expression block_expr1 = c.make_node<Integer>(l, 42UL);
  auto *block1 = c.make_node<BlockExpr>(l,
                                        std::move(stmts1),
                                        std::move(block_expr1));

  Expression cond2 = c.make_node<Boolean>(l, false);
  StatementList stmts2;
  Expression block_expr2 = c.make_node<Integer>(l, 24UL);
  auto *block2 = c.make_node<BlockExpr>(l,
                                        std::move(stmts2),
                                        std::move(block_expr2));

  Expression cond3 = c.make_node<Variable>(l, std::string("$flag"));
  StatementList stmts3;
  Expression block_expr3 = c.make_node<String>(l, std::string("loop"));
  auto *block3 = c.make_node<BlockExpr>(l,
                                        std::move(stmts3),
                                        std::move(block_expr3));

  Expression cond4 = c.make_node<Boolean>(l, true);
  StatementList stmts4;
  Expression block_expr4 = c.make_node<Integer>(l, 100UL);
  auto *block4 = c.make_node<BlockExpr>(l,
                                        std::move(stmts4),
                                        std::move(block_expr4));

  return { c.make_node<While>(l, std::move(cond1), block1),
           c.make_node<While>(l, std::move(cond2), block2),
           c.make_node<While>(l, std::move(cond3), block3),
           c.make_node<While>(l, std::move(cond4), block4) };
}

template <>
std::vector<For *> variants<For>(ASTContext &c, SourceLocation l)
{
  auto *decl1 = c.make_node<Variable>(l, std::string("$i"));
  auto *map1 = c.make_node<Map>(l, std::string("@data"));
  Iterable iterable1 = map1;
  StatementList stmts1;
  Expression block_expr1 = c.make_node<Integer>(l, 42UL);
  auto *block1 = c.make_node<BlockExpr>(l,
                                        std::move(stmts1),
                                        std::move(block_expr1));

  auto *decl2 = c.make_node<Variable>(l, std::string("$j"));
  auto *map2 = c.make_node<Map>(l, std::string("@other"));
  Iterable iterable2 = map2;
  StatementList stmts2;
  Expression block_expr2 = c.make_node<Integer>(l, 24UL);
  auto *block2 = c.make_node<BlockExpr>(l,
                                        std::move(stmts2),
                                        std::move(block_expr2));

  auto *decl3 = c.make_node<Variable>(l, std::string("$k"));
  Expression start = c.make_node<Integer>(l, 0UL);
  Expression end = c.make_node<Integer>(l, 10UL);
  auto *range = c.make_node<Range>(l, std::move(start), std::move(end));
  Iterable iterable3 = range;
  StatementList stmts3;
  Expression block_expr3 = c.make_node<String>(l, std::string("loop"));
  auto *block3 = c.make_node<BlockExpr>(l,
                                        std::move(stmts3),
                                        std::move(block_expr3));

  auto *decl4 = c.make_node<Variable>(l, std::string("$i"));
  auto *map4 = c.make_node<Map>(l, std::string("@count"));
  Iterable iterable4 = map4;
  StatementList stmts4;
  Expression block_expr4 = c.make_node<Integer>(l, 100UL);
  auto *block4 = c.make_node<BlockExpr>(l,
                                        std::move(stmts4),
                                        std::move(block_expr4));

  return { c.make_node<For>(l, decl1, std::move(iterable1), block1),
           c.make_node<For>(l, decl2, std::move(iterable2), block2),
           c.make_node<For>(l, decl3, std::move(iterable3), block3),
           c.make_node<For>(l, decl4, std::move(iterable4), block4) };
}

template <>
std::vector<Range *> variants<Range>(ASTContext &c, SourceLocation l)
{
  Expression start1 = c.make_node<Integer>(l, 0UL);
  Expression end1 = c.make_node<Integer>(l, 10UL);

  Expression start2 = c.make_node<Integer>(l, 1UL);
  Expression end2 = c.make_node<Integer>(l, 5UL);

  Expression start3 = c.make_node<Variable>(l, std::string("$start"));
  Expression end3 = c.make_node<Variable>(l, std::string("$end"));

  Expression start4 = c.make_node<Integer>(l, 0UL);
  Expression end4 = c.make_node<Integer>(l, 100UL);

  return { c.make_node<Range>(l, std::move(start1), std::move(end1)),
           c.make_node<Range>(l, std::move(start2), std::move(end2)),
           c.make_node<Range>(l, std::move(start3), std::move(end3)),
           c.make_node<Range>(l, std::move(start4), std::move(end4)) };
}

template <>
std::vector<Expression> variants<Expression>(ASTContext &c, SourceLocation l)
{
  // Include same type with different values and different types
  return {
    c.make_node<Integer>(l, 42UL),                 // Primary variant
    c.make_node<Integer>(l, 24UL),                 // Same type, different value
    c.make_node<String>(l, std::string("test")),   // Different type
    c.make_node<Boolean>(l, true),                 // Different type
    c.make_node<Variable>(l, std::string("$var")), // Different type
    c.make_node<NegativeInteger>(l, -10L)          // Different type
  };
}

template <>
std::vector<Statement> variants<Statement>(ASTContext &c, SourceLocation l)
{
  // Include same type with different values and different types
  Expression expr1 = c.make_node<Integer>(l, 42UL);
  Expression expr2 = c.make_node<Integer>(l, 24UL);
  auto *var = c.make_node<Variable>(l, std::string("$var"));
  auto *typeof_node = c.make_node<Typeof>(l, CreateInt32());
  auto *map = c.make_node<Map>(l, std::string("@map"));
  Expression expr3 = c.make_node<String>(l, std::string("value"));

  return {
    c.make_node<ExprStatement>(l, std::move(expr1)),    // Primary variant
    c.make_node<ExprStatement>(l, std::move(expr2)),    // Same type, different
                                                        // value
    c.make_node<VarDeclStatement>(l, var, typeof_node), // Different type
    c.make_node<AssignScalarMapStatement>(l,
                                          map,
                                          std::move(expr3)), // Different
                                                             // type
    c.make_node<Jump>(l, JumpType::RETURN),                  // Different type
  };
}

template <>
std::vector<Iterable> variants<Iterable>(ASTContext &c, SourceLocation l)
{
  auto *map1 = c.make_node<Map>(l, std::string("@map"));
  auto *map2 = c.make_node<Map>(l, std::string("@other"));

  Expression start1 = c.make_node<Integer>(l, 0UL);
  Expression end1 = c.make_node<Integer>(l, 10UL);
  auto *range1 = c.make_node<Range>(l, std::move(start1), std::move(end1));

  auto *map3 = c.make_node<Map>(l, std::string("@data"));

  Expression start2 = c.make_node<Integer>(l, 5UL);
  Expression end2 = c.make_node<Integer>(l, 15UL);
  auto *range2 = c.make_node<Range>(l, std::move(start2), std::move(end2));

  return {
    map1,   // Primary variant
    map2,   // Same type, different value
    range1, // Different type
    map3,   // Same type, different value
    range2  // Different type
  };
}

using TestTypes = ::testing::Types<Integer,
                                   NegativeInteger,
                                   Boolean,
                                   String,
                                   None,
                                   Identifier,
                                   Builtin,
                                   Variable,
                                   Map,
                                   PositionalParameter,
                                   PositionalParameterCount,
                                   Call,
                                   Sizeof,
                                   Offsetof,
                                   VariableAddr,
                                   MapAddr,
                                   Binop,
                                   Unop,
                                   FieldAccess,
                                   ArrayAccess,
                                   TupleAccess,
                                   MapAccess,
                                   Cast,
                                   Tuple,
                                   IfExpr,
                                   BlockExpr,
                                   Typeinfo,
                                   Comptime,
                                   ExprStatement,
                                   VarDeclStatement,
                                   AssignScalarMapStatement,
                                   AssignMapStatement,
                                   AssignVarStatement,
                                   Unroll,
                                   Jump,
                                   While,
                                   For,
                                   Range>;

template <typename T>
class ASTTest : public ::testing::Test {
protected:
  ASTContext ctx;
  SourceLocation loc;
};

TYPED_TEST_SUITE(ASTTest, TestTypes);

template <typename T>
const auto &deref(const T &t)
{
  if constexpr (std::is_pointer_v<T>) {
    return *t;
  } else {
    return t;
  }
}

TYPED_TEST(ASTTest, Cloning)
{
  auto nodes = variants<TypeParam>(this->ctx, this->loc);
  ASSERT_FALSE(nodes.empty());

  for (size_t i = 0; i < nodes.size(); ++i) {
    auto *cloned = clone(this->ctx, Location(), nodes[i]);
    for (size_t j = 0; j < nodes.size(); ++j) {
      if (j == i) {
        EXPECT_EQ(deref(cloned), deref(nodes[j]));
        EXPECT_EQ(deref(cloned) <=> deref(nodes[j]),
                  std::partial_ordering::equivalent);
      } else {
        EXPECT_NE(deref(cloned), deref(nodes[j]));
        EXPECT_NE(deref(cloned) <=> deref(nodes[j]),
                  std::partial_ordering::equivalent);
      }
    }
  }
}

TYPED_TEST(ASTTest, Comparison)
{
  auto nodes = variants<TypeParam>(this->ctx, this->loc);
  ASSERT_FALSE(nodes.empty());

  const auto &node1 = nodes[0];
  const auto &node2 = nodes[0];
  EXPECT_EQ(deref(node1), deref(node2));
  EXPECT_EQ(deref(node1) <=> deref(node2), std::partial_ordering::equivalent);

  std::stable_sort(nodes.begin(),
                   nodes.end(),
                   [&](const auto &a, const auto &b) -> bool {
                     return deref(a) < deref(b);
                   });

  for (size_t i = 0; i < nodes.size(); ++i) {
    for (size_t j = i + 1; j < nodes.size(); ++j) {
      EXPECT_LT(deref(nodes[i]), deref(nodes[j]));
      EXPECT_EQ(deref(nodes[i]) <=> deref(nodes[j]),
                std::partial_ordering::less);
    }
  }
}

} // namespace bpftrace::test::ast
