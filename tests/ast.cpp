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
  return { c.make_node<Integer>(42UL, l),
           c.make_node<Integer>(24UL, l),
           c.make_node<Integer>(100UL, l),
           c.make_node<Integer>(0UL, l) };
}

template <>
std::vector<NegativeInteger *> variants<NegativeInteger>(ASTContext &c,
                                                         SourceLocation l)
{
  return { c.make_node<NegativeInteger>(-42L, l),
           c.make_node<NegativeInteger>(-24L, l),
           c.make_node<NegativeInteger>(-100L, l),
           c.make_node<NegativeInteger>(-1L, l) };
}

template <>
std::vector<Boolean *> variants<Boolean>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Boolean>(true, l), c.make_node<Boolean>(false, l) };
}

template <>
std::vector<String *> variants<String>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<String>(std::string("test"), l),
           c.make_node<String>(std::string("different"), l),
           c.make_node<String>(std::string("another"), l),
           c.make_node<String>(std::string(""), l) };
}

template <>
std::vector<None *> variants<None>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<None>(l) };
}

template <>
std::vector<Identifier *> variants<Identifier>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Identifier>(std::string("var"), l),
           c.make_node<Identifier>(std::string("other"), l),
           c.make_node<Identifier>(std::string("xyz"), l),
           c.make_node<Identifier>(std::string("_test"), l) };
}

template <>
std::vector<Builtin *> variants<Builtin>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Builtin>(std::string("pid"), l),
           c.make_node<Builtin>(std::string("tid"), l),
           c.make_node<Builtin>(std::string("uid"), l),
           c.make_node<Builtin>(std::string("comm"), l) };
}

template <>
std::vector<Variable *> variants<Variable>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Variable>(std::string("$var"), l),
           c.make_node<Variable>(std::string("$other"), l),
           c.make_node<Variable>(std::string("$x"), l),
           c.make_node<Variable>(std::string("$test123"), l) };
}

template <>
std::vector<Map *> variants<Map>(ASTContext &c, SourceLocation l)
{
  return { c.make_node<Map>(std::string("@map"), l),
           c.make_node<Map>(std::string("@other"), l),
           c.make_node<Map>(std::string("@data"), l),
           c.make_node<Map>(std::string("@count"), l) };
}

template <>
std::vector<PositionalParameter *> variants<PositionalParameter>(
    ASTContext &c,
    SourceLocation l)
{
  return { c.make_node<PositionalParameter>(1L, l),
           c.make_node<PositionalParameter>(2L, l),
           c.make_node<PositionalParameter>(0L, l),
           c.make_node<PositionalParameter>(10L, l) };
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
  args1.emplace_back(c.make_node<Integer>(1UL, l));

  ExpressionList args2;
  args2.emplace_back(c.make_node<String>(std::string("test"), l));

  ExpressionList args3;
  args3.emplace_back(c.make_node<Integer>(2UL, l));
  args3.emplace_back(c.make_node<String>(std::string("arg"), l));

  ExpressionList args4;

  return { c.make_node<Call>(std::string("printf"), std::move(args1), l),
           c.make_node<Call>(std::string("count"), std::move(args4), l),
           c.make_node<Call>(std::string("printf"), std::move(args2), l),
           c.make_node<Call>(std::string("printf"), std::move(args3), l) };
}

template <>
std::vector<Sizeof *> variants<Sizeof>(ASTContext &c, SourceLocation l)
{
  Expression expr = c.make_node<Integer>(42UL, l);
  return { c.make_node<Sizeof>(CreateInt32(), l),
           c.make_node<Sizeof>(CreateInt64(), l),
           c.make_node<Sizeof>(CreateUInt32(), l),
           c.make_node<Sizeof>(std::move(expr), l) };
}

template <>
std::vector<Offsetof *> variants<Offsetof>(ASTContext &c, SourceLocation l)
{
  std::vector<std::string> field1 = { "field" };
  std::vector<std::string> field2 = { "other" };
  std::vector<std::string> field3 = { "field", "nested" };
  Expression expr = c.make_node<Variable>(std::string("$var"), l);
  std::vector<std::string> field4 = { "member" };

  return { c.make_node<Offsetof>(CreateInteger(32, false), field1, l),
           c.make_node<Offsetof>(CreateInteger(64, false), field2, l),
           c.make_node<Offsetof>(CreateString(64), field3, l),
           c.make_node<Offsetof>(std::move(expr), field4, l) };
}

template <>
std::vector<VariableAddr *> variants<VariableAddr>(ASTContext &c,
                                                   SourceLocation l)
{
  auto *var1 = c.make_node<Variable>(std::string("$var"), l);
  auto *var2 = c.make_node<Variable>(std::string("$other"), l);
  auto *var3 = c.make_node<Variable>(std::string("$x"), l);

  return { c.make_node<VariableAddr>(var1, l),
           c.make_node<VariableAddr>(var2, l),
           c.make_node<VariableAddr>(var3, l) };
}

template <>
std::vector<MapAddr *> variants<MapAddr>(ASTContext &c, SourceLocation l)
{
  auto *map1 = c.make_node<Map>(std::string("@map"), l);
  auto *map2 = c.make_node<Map>(std::string("@other"), l);
  auto *map3 = c.make_node<Map>(std::string("@data"), l);

  return { c.make_node<MapAddr>(map1, l),
           c.make_node<MapAddr>(map2, l),
           c.make_node<MapAddr>(map3, l) };
}

template <>
std::vector<Binop *> variants<Binop>(ASTContext &c, SourceLocation l)
{
  Expression left1 = c.make_node<Integer>(1UL, l);
  Expression right1 = c.make_node<Integer>(2UL, l);

  Expression left2 = c.make_node<Integer>(3UL, l);
  Expression right2 = c.make_node<Integer>(4UL, l);

  Expression left3 = c.make_node<Integer>(1UL, l);
  Expression right3 = c.make_node<Integer>(2UL, l);

  Expression left4 = c.make_node<Variable>(std::string("$x"), l);
  Expression right4 = c.make_node<Integer>(5UL, l);

  return {
    c.make_node<Binop>(std::move(left1), Operator::PLUS, std::move(right1), l),
    c.make_node<Binop>(std::move(left2), Operator::MINUS, std::move(right2), l),
    c.make_node<Binop>(std::move(left3), Operator::MUL, std::move(right3), l),
    c.make_node<Binop>(std::move(left4), Operator::PLUS, std::move(right4), l)
  };
}

template <>
std::vector<Unop *> variants<Unop>(ASTContext &c, SourceLocation l)
{
  Expression expr1 = c.make_node<Integer>(42UL, l);
  Expression expr2 = c.make_node<Integer>(24UL, l);
  Expression expr3 = c.make_node<Variable>(std::string("$x"), l);

  return { c.make_node<Unop>(std::move(expr1), Operator::LNOT, l),
           c.make_node<Unop>(std::move(expr2), Operator::BNOT, l),
           c.make_node<Unop>(std::move(expr3), Operator::LNOT, l) };
}

template <>
std::vector<FieldAccess *> variants<FieldAccess>(ASTContext &c,
                                                 SourceLocation l)
{
  Expression expr1 = c.make_node<Variable>(std::string("$var"), l);
  Expression expr2 = c.make_node<Variable>(std::string("$other"), l);
  Expression expr3 = c.make_node<Variable>(std::string("$var"), l);
  Expression expr4 = c.make_node<Builtin>(std::string("pid"), l);

  return {
    c.make_node<FieldAccess>(std::move(expr1), std::string("field"), l),
    c.make_node<FieldAccess>(std::move(expr2), std::string("field"), l),
    c.make_node<FieldAccess>(std::move(expr3), std::string("other"), l),
    c.make_node<FieldAccess>(std::move(expr4), std::string("member"), l)
  };
}

template <>
std::vector<ArrayAccess *> variants<ArrayAccess>(ASTContext &c,
                                                 SourceLocation l)
{
  Expression expr1 = c.make_node<Variable>(std::string("$arr"), l);
  Expression index1 = c.make_node<Integer>(0UL, l);

  Expression expr2 = c.make_node<Variable>(std::string("$other"), l);
  Expression index2 = c.make_node<Integer>(1UL, l);

  Expression expr3 = c.make_node<Variable>(std::string("$arr"), l);
  Expression index3 = c.make_node<Integer>(2UL, l);

  Expression expr4 = c.make_node<Map>(std::string("@data"), l);
  Expression index4 = c.make_node<Variable>(std::string("$key"), l);

  return { c.make_node<ArrayAccess>(std::move(expr1), std::move(index1), l),
           c.make_node<ArrayAccess>(std::move(expr2), std::move(index2), l),
           c.make_node<ArrayAccess>(std::move(expr3), std::move(index3), l),
           c.make_node<ArrayAccess>(std::move(expr4), std::move(index4), l) };
}

template <>
std::vector<TupleAccess *> variants<TupleAccess>(ASTContext &c,
                                                 SourceLocation l)
{
  Expression expr1 = c.make_node<Variable>(std::string("$tuple"), l);
  Expression expr2 = c.make_node<Variable>(std::string("$other"), l);
  Expression expr3 = c.make_node<Variable>(std::string("$tuple"), l);
  Expression expr4 = c.make_node<Variable>(std::string("$xyz"), l);

  return { c.make_node<TupleAccess>(std::move(expr1), 0, l),
           c.make_node<TupleAccess>(std::move(expr2), 0, l),
           c.make_node<TupleAccess>(std::move(expr3), 1, l),
           c.make_node<TupleAccess>(std::move(expr4), 2, l) };
}

template <>
std::vector<MapAccess *> variants<MapAccess>(ASTContext &c, SourceLocation l)
{
  auto *map1 = c.make_node<Map>(std::string("@map"), l);
  Expression key1 = c.make_node<Integer>(1UL, l);

  auto *map2 = c.make_node<Map>(std::string("@other"), l);
  Expression key2 = c.make_node<Integer>(2UL, l);

  auto *map3 = c.make_node<Map>(std::string("@map"), l);
  Expression key3 = c.make_node<String>(std::string("key"), l);

  auto *map4 = c.make_node<Map>(std::string("@data"), l);
  Expression key4 = c.make_node<Variable>(std::string("$key"), l);

  return { c.make_node<MapAccess>(map1, std::move(key1), l),
           c.make_node<MapAccess>(map2, std::move(key2), l),
           c.make_node<MapAccess>(map3, std::move(key3), l),
           c.make_node<MapAccess>(map4, std::move(key4), l) };
}

template <>
std::vector<Cast *> variants<Cast>(ASTContext &c, SourceLocation l)
{
  auto *typeof1 = c.make_node<Typeof>(CreateInt32(), l);
  Expression expr1 = c.make_node<Integer>(42UL, l);

  auto *typeof2 = c.make_node<Typeof>(CreateInt64(), l);
  Expression expr2 = c.make_node<Integer>(24UL, l);

  auto *typeof3 = c.make_node<Typeof>(CreateInt32(), l);
  Expression expr3 = c.make_node<Variable>(std::string("$x"), l);

  auto *typeof4 = c.make_node<Typeof>(CreateUInt32(), l);
  Expression expr4 = c.make_node<Integer>(42UL, l);

  return { c.make_node<Cast>(typeof1, std::move(expr1), l),
           c.make_node<Cast>(typeof2, std::move(expr2), l),
           c.make_node<Cast>(typeof3, std::move(expr3), l),
           c.make_node<Cast>(typeof4, std::move(expr4), l) };
}

template <>
std::vector<Tuple *> variants<Tuple>(ASTContext &c, SourceLocation l)
{
  ExpressionList elems1;
  elems1.emplace_back(c.make_node<Integer>(1UL, l));
  elems1.emplace_back(c.make_node<Integer>(2UL, l));

  ExpressionList elems2;
  elems2.emplace_back(c.make_node<Integer>(3UL, l));
  elems2.emplace_back(c.make_node<Integer>(4UL, l));

  ExpressionList elems3;
  elems3.emplace_back(c.make_node<String>(std::string("a"), l));
  elems3.emplace_back(c.make_node<String>(std::string("b"), l));

  ExpressionList elems4;
  elems4.emplace_back(c.make_node<Integer>(1UL, l));
  elems4.emplace_back(c.make_node<String>(std::string("mixed"), l));
  elems4.emplace_back(c.make_node<Boolean>(true, l));

  return { c.make_node<Tuple>(std::move(elems1), l),
           c.make_node<Tuple>(std::move(elems2), l),
           c.make_node<Tuple>(std::move(elems3), l),
           c.make_node<Tuple>(std::move(elems4), l) };
}

template <>
std::vector<IfExpr *> variants<IfExpr>(ASTContext &c, SourceLocation l)
{
  Expression cond1 = c.make_node<Boolean>(true, l);
  Expression left1 = c.make_node<Integer>(1UL, l);
  Expression right1 = c.make_node<Integer>(2UL, l);

  Expression cond2 = c.make_node<Boolean>(false, l);
  Expression left2 = c.make_node<Integer>(3UL, l);
  Expression right2 = c.make_node<Integer>(4UL, l);

  Expression cond3 = c.make_node<Variable>(std::string("$flag"), l);
  Expression left3 = c.make_node<String>(std::string("yes"), l);
  Expression right3 = c.make_node<String>(std::string("no"), l);

  Expression cond4 = c.make_node<Boolean>(true, l);
  Expression left4 = c.make_node<Integer>(10UL, l);
  Expression right4 = c.make_node<Integer>(20UL, l);

  return { c.make_node<IfExpr>(
               std::move(cond1), std::move(left1), std::move(right1), l),
           c.make_node<IfExpr>(
               std::move(cond2), std::move(left2), std::move(right2), l),
           c.make_node<IfExpr>(
               std::move(cond3), std::move(left3), std::move(right3), l),
           c.make_node<IfExpr>(
               std::move(cond4), std::move(left4), std::move(right4), l) };
}

template <>
std::vector<BlockExpr *> variants<BlockExpr>(ASTContext &c, SourceLocation l)
{
  StatementList stmts1;
  Expression expr1 = c.make_node<Integer>(42UL, l);

  StatementList stmts2;
  Expression expr2 = c.make_node<Integer>(24UL, l);

  StatementList stmts3;
  Expression stmt_expr = c.make_node<Variable>(std::string("$x"), l);
  stmts3.emplace_back(c.make_node<ExprStatement>(std::move(stmt_expr), l));
  Expression expr3 = c.make_node<String>(std::string("result"), l);

  StatementList stmts4;
  Expression expr4 = c.make_node<Boolean>(true, l);

  return { c.make_node<BlockExpr>(std::move(stmts1), std::move(expr1), l),
           c.make_node<BlockExpr>(std::move(stmts2), std::move(expr2), l),
           c.make_node<BlockExpr>(std::move(stmts3), std::move(expr3), l),
           c.make_node<BlockExpr>(std::move(stmts4), std::move(expr4), l) };
}

template <>
std::vector<Typeinfo *> variants<Typeinfo>(ASTContext &c, SourceLocation l)
{
  auto *typeof1 = c.make_node<Typeof>(CreateInt32(), l);
  auto *typeof2 = c.make_node<Typeof>(CreateInt64(), l);
  auto *typeof3 = c.make_node<Typeof>(CreateUInt32(), l);
  Expression expr = c.make_node<Variable>(std::string("$x"), l);
  auto *typeof4 = c.make_node<Typeof>(std::move(expr), l);

  return { c.make_node<Typeinfo>(typeof1, l),
           c.make_node<Typeinfo>(typeof2, l),
           c.make_node<Typeinfo>(typeof3, l),
           c.make_node<Typeinfo>(typeof4, l) };
}

template <>
std::vector<Comptime *> variants<Comptime>(ASTContext &c, SourceLocation l)
{
  Expression expr1 = c.make_node<Integer>(42UL, l);
  Expression expr2 = c.make_node<Integer>(24UL, l);
  Expression expr3 = c.make_node<String>(std::string("test"), l);
  Expression expr4 = c.make_node<Variable>(std::string("$x"), l);

  return { c.make_node<Comptime>(std::move(expr1), l),
           c.make_node<Comptime>(std::move(expr2), l),
           c.make_node<Comptime>(std::move(expr3), l),
           c.make_node<Comptime>(std::move(expr4), l) };
}

template <>
std::vector<ExprStatement *> variants<ExprStatement>(ASTContext &c,
                                                     SourceLocation l)
{
  Expression expr1 = c.make_node<Integer>(42UL, l);
  Expression expr2 = c.make_node<Integer>(24UL, l);
  Expression expr3 = c.make_node<String>(std::string("test"), l);
  Expression expr4 = c.make_node<Variable>(std::string("$x"), l);

  return { c.make_node<ExprStatement>(std::move(expr1), l),
           c.make_node<ExprStatement>(std::move(expr2), l),
           c.make_node<ExprStatement>(std::move(expr3), l),
           c.make_node<ExprStatement>(std::move(expr4), l) };
}

template <>
std::vector<VarDeclStatement *> variants<VarDeclStatement>(ASTContext &c,
                                                           SourceLocation l)
{
  auto *var1 = c.make_node<Variable>(std::string("$var"), l);
  auto *typeof1 = c.make_node<Typeof>(CreateInt32(), l);

  auto *var2 = c.make_node<Variable>(std::string("$other"), l);
  auto *typeof2 = c.make_node<Typeof>(CreateInt64(), l);

  auto *var3 = c.make_node<Variable>(std::string("$x"), l);
  auto *typeof3 = c.make_node<Typeof>(CreateUInt32(), l);

  auto *var4 = c.make_node<Variable>(std::string("$test"), l);
  auto *typeof4 = c.make_node<Typeof>(CreateInt32(), l);

  return { c.make_node<VarDeclStatement>(var1, typeof1, l),
           c.make_node<VarDeclStatement>(var2, typeof2, l),
           c.make_node<VarDeclStatement>(var3, typeof3, l),
           c.make_node<VarDeclStatement>(var4, typeof4, l) };
}

template <>
std::vector<AssignScalarMapStatement *> variants<AssignScalarMapStatement>(
    ASTContext &c,
    SourceLocation l)
{
  auto *map1 = c.make_node<Map>(std::string("@map"), l);
  Expression expr1 = c.make_node<Integer>(42UL, l);

  auto *map2 = c.make_node<Map>(std::string("@other"), l);
  Expression expr2 = c.make_node<Integer>(24UL, l);

  auto *map3 = c.make_node<Map>(std::string("@map"), l);
  Expression expr3 = c.make_node<String>(std::string("value"), l);

  auto *map4 = c.make_node<Map>(std::string("@data"), l);
  Expression expr4 = c.make_node<Variable>(std::string("$x"), l);

  return { c.make_node<AssignScalarMapStatement>(map1, std::move(expr1), l),
           c.make_node<AssignScalarMapStatement>(map2, std::move(expr2), l),
           c.make_node<AssignScalarMapStatement>(map3, std::move(expr3), l),
           c.make_node<AssignScalarMapStatement>(map4, std::move(expr4), l) };
}

template <>
std::vector<AssignMapStatement *> variants<AssignMapStatement>(ASTContext &c,
                                                               SourceLocation l)
{
  auto *map1 = c.make_node<Map>(std::string("@map"), l);
  Expression key1 = c.make_node<Integer>(1UL, l);
  Expression expr1 = c.make_node<Integer>(42UL, l);

  auto *map2 = c.make_node<Map>(std::string("@other"), l);
  Expression key2 = c.make_node<Integer>(2UL, l);
  Expression expr2 = c.make_node<Integer>(24UL, l);

  auto *map3 = c.make_node<Map>(std::string("@map"), l);
  Expression key3 = c.make_node<String>(std::string("key"), l);
  Expression expr3 = c.make_node<String>(std::string("value"), l);

  auto *map4 = c.make_node<Map>(std::string("@data"), l);
  Expression key4 = c.make_node<Variable>(std::string("$k"), l);
  Expression expr4 = c.make_node<Variable>(std::string("$v"), l);

  return {
    c.make_node<AssignMapStatement>(map1, std::move(key1), std::move(expr1), l),
    c.make_node<AssignMapStatement>(map2, std::move(key2), std::move(expr2), l),
    c.make_node<AssignMapStatement>(map3, std::move(key3), std::move(expr3), l),
    c.make_node<AssignMapStatement>(map4, std::move(key4), std::move(expr4), l)
  };
}

template <>
std::vector<AssignVarStatement *> variants<AssignVarStatement>(ASTContext &c,
                                                               SourceLocation l)
{
  auto *var1 = c.make_node<Variable>(std::string("$var"), l);
  Expression expr1 = c.make_node<Integer>(42UL, l);

  auto *var2 = c.make_node<Variable>(std::string("$other"), l);
  Expression expr2 = c.make_node<Integer>(24UL, l);

  auto *var3 = c.make_node<Variable>(std::string("$var"), l);
  Expression expr3 = c.make_node<String>(std::string("value"), l);

  auto *var4 = c.make_node<Variable>(std::string("$x"), l);
  Expression expr4 = c.make_node<Boolean>(true, l);

  return { c.make_node<AssignVarStatement>(var1, std::move(expr1), l),
           c.make_node<AssignVarStatement>(var2, std::move(expr2), l),
           c.make_node<AssignVarStatement>(var3, std::move(expr3), l),
           c.make_node<AssignVarStatement>(var4, std::move(expr4), l) };
}

template <>
std::vector<Unroll *> variants<Unroll>(ASTContext &c, SourceLocation l)
{
  Expression expr1 = c.make_node<Integer>(10UL, l);
  StatementList stmts1;
  Expression block_expr1 = c.make_node<Integer>(1UL, l);
  auto *block1 = c.make_node<BlockExpr>(std::move(stmts1),
                                        std::move(block_expr1),
                                        l);

  Expression expr2 = c.make_node<Integer>(5UL, l);
  StatementList stmts2;
  Expression block_expr2 = c.make_node<Integer>(2UL, l);
  auto *block2 = c.make_node<BlockExpr>(std::move(stmts2),
                                        std::move(block_expr2),
                                        l);

  Expression expr3 = c.make_node<Variable>(std::string("$count"), l);
  StatementList stmts3;
  Expression block_expr3 = c.make_node<String>(std::string("loop"), l);
  auto *block3 = c.make_node<BlockExpr>(std::move(stmts3),
                                        std::move(block_expr3),
                                        l);

  Expression expr4 = c.make_node<Integer>(10UL, l);
  StatementList stmts4;
  Expression block_expr4 = c.make_node<Integer>(3UL, l);
  auto *block4 = c.make_node<BlockExpr>(std::move(stmts4),
                                        std::move(block_expr4),
                                        l);

  return { c.make_node<Unroll>(std::move(expr1), block1, l),
           c.make_node<Unroll>(std::move(expr2), block2, l),
           c.make_node<Unroll>(std::move(expr3), block3, l),
           c.make_node<Unroll>(std::move(expr4), block4, l) };
}

template <>
std::vector<Jump *> variants<Jump>(ASTContext &c, SourceLocation l)
{
  Expression return_val1 = c.make_node<Integer>(42UL, l);
  Expression return_val2 = c.make_node<String>(std::string("done"), l);

  return { c.make_node<Jump>(JumpType::RETURN, l),
           c.make_node<Jump>(JumpType::CONTINUE, l),
           c.make_node<Jump>(JumpType::BREAK, l),
           c.make_node<Jump>(JumpType::RETURN, std::move(return_val1), l),
           c.make_node<Jump>(JumpType::RETURN, std::move(return_val2), l) };
}

template <>
std::vector<While *> variants<While>(ASTContext &c, SourceLocation l)
{
  Expression cond1 = c.make_node<Boolean>(true, l);
  StatementList stmts1;
  Expression block_expr1 = c.make_node<Integer>(42UL, l);
  auto *block1 = c.make_node<BlockExpr>(std::move(stmts1),
                                        std::move(block_expr1),
                                        l);

  Expression cond2 = c.make_node<Boolean>(false, l);
  StatementList stmts2;
  Expression block_expr2 = c.make_node<Integer>(24UL, l);
  auto *block2 = c.make_node<BlockExpr>(std::move(stmts2),
                                        std::move(block_expr2),
                                        l);

  Expression cond3 = c.make_node<Variable>(std::string("$flag"), l);
  StatementList stmts3;
  Expression block_expr3 = c.make_node<String>(std::string("loop"), l);
  auto *block3 = c.make_node<BlockExpr>(std::move(stmts3),
                                        std::move(block_expr3),
                                        l);

  Expression cond4 = c.make_node<Boolean>(true, l);
  StatementList stmts4;
  Expression block_expr4 = c.make_node<Integer>(100UL, l);
  auto *block4 = c.make_node<BlockExpr>(std::move(stmts4),
                                        std::move(block_expr4),
                                        l);

  return { c.make_node<While>(std::move(cond1), block1, l),
           c.make_node<While>(std::move(cond2), block2, l),
           c.make_node<While>(std::move(cond3), block3, l),
           c.make_node<While>(std::move(cond4), block4, l) };
}

template <>
std::vector<For *> variants<For>(ASTContext &c, SourceLocation l)
{
  auto *decl1 = c.make_node<Variable>(std::string("$i"), l);
  auto *map1 = c.make_node<Map>(std::string("@data"), l);
  Iterable iterable1 = map1;
  StatementList stmts1;
  Expression block_expr1 = c.make_node<Integer>(42UL, l);
  auto *block1 = c.make_node<BlockExpr>(std::move(stmts1),
                                        std::move(block_expr1),
                                        l);

  auto *decl2 = c.make_node<Variable>(std::string("$j"), l);
  auto *map2 = c.make_node<Map>(std::string("@other"), l);
  Iterable iterable2 = map2;
  StatementList stmts2;
  Expression block_expr2 = c.make_node<Integer>(24UL, l);
  auto *block2 = c.make_node<BlockExpr>(std::move(stmts2),
                                        std::move(block_expr2),
                                        l);

  auto *decl3 = c.make_node<Variable>(std::string("$k"), l);
  Expression start = c.make_node<Integer>(0UL, l);
  Expression end = c.make_node<Integer>(10UL, l);
  auto *range = c.make_node<Range>(std::move(start), std::move(end), l);
  Iterable iterable3 = range;
  StatementList stmts3;
  Expression block_expr3 = c.make_node<String>(std::string("loop"), l);
  auto *block3 = c.make_node<BlockExpr>(std::move(stmts3),
                                        std::move(block_expr3),
                                        l);

  auto *decl4 = c.make_node<Variable>(std::string("$i"), l);
  auto *map4 = c.make_node<Map>(std::string("@count"), l);
  Iterable iterable4 = map4;
  StatementList stmts4;
  Expression block_expr4 = c.make_node<Integer>(100UL, l);
  auto *block4 = c.make_node<BlockExpr>(std::move(stmts4),
                                        std::move(block_expr4),
                                        l);

  return { c.make_node<For>(decl1, std::move(iterable1), block1, l),
           c.make_node<For>(decl2, std::move(iterable2), block2, l),
           c.make_node<For>(decl3, std::move(iterable3), block3, l),
           c.make_node<For>(decl4, std::move(iterable4), block4, l) };
}

template <>
std::vector<Range *> variants<Range>(ASTContext &c, SourceLocation l)
{
  Expression start1 = c.make_node<Integer>(0UL, l);
  Expression end1 = c.make_node<Integer>(10UL, l);

  Expression start2 = c.make_node<Integer>(1UL, l);
  Expression end2 = c.make_node<Integer>(5UL, l);

  Expression start3 = c.make_node<Variable>(std::string("$start"), l);
  Expression end3 = c.make_node<Variable>(std::string("$end"), l);

  Expression start4 = c.make_node<Integer>(0UL, l);
  Expression end4 = c.make_node<Integer>(100UL, l);

  return { c.make_node<Range>(std::move(start1), std::move(end1), l),
           c.make_node<Range>(std::move(start2), std::move(end2), l),
           c.make_node<Range>(std::move(start3), std::move(end3), l),
           c.make_node<Range>(std::move(start4), std::move(end4), l) };
}

template <>
std::vector<Expression> variants<Expression>(ASTContext &c, SourceLocation l)
{
  // Include same type with different values and different types
  return {
    c.make_node<Integer>(42UL, l),                 // Primary variant
    c.make_node<Integer>(24UL, l),                 // Same type, different value
    c.make_node<String>(std::string("test"), l),   // Different type
    c.make_node<Boolean>(true, l),                 // Different type
    c.make_node<Variable>(std::string("$var"), l), // Different type
    c.make_node<NegativeInteger>(-10L, l)          // Different type
  };
}

template <>
std::vector<Statement> variants<Statement>(ASTContext &c, SourceLocation l)
{
  // Include same type with different values and different types
  Expression expr1 = c.make_node<Integer>(42UL, l);
  Expression expr2 = c.make_node<Integer>(24UL, l);
  auto *var = c.make_node<Variable>(std::string("$var"), l);
  auto *typeof_node = c.make_node<Typeof>(CreateInt32(), l);
  auto *map = c.make_node<Map>(std::string("@map"), l);
  Expression expr3 = c.make_node<String>(std::string("value"), l);

  return {
    c.make_node<ExprStatement>(std::move(expr1), l),    // Primary variant
    c.make_node<ExprStatement>(std::move(expr2), l),    // Same type, different
                                                        // value
    c.make_node<VarDeclStatement>(var, typeof_node, l), // Different type
    c.make_node<AssignScalarMapStatement>(map,
                                          std::move(expr3),
                                          l), // Different
                                              // type
    c.make_node<Jump>(JumpType::RETURN, l),   // Different type
  };
}

template <>
std::vector<Iterable> variants<Iterable>(ASTContext &c, SourceLocation l)
{
  auto *map1 = c.make_node<Map>(std::string("@map"), l);
  auto *map2 = c.make_node<Map>(std::string("@other"), l);

  Expression start1 = c.make_node<Integer>(0UL, l);
  Expression end1 = c.make_node<Integer>(10UL, l);
  auto *range1 = c.make_node<Range>(std::move(start1), std::move(end1), l);

  auto *map3 = c.make_node<Map>(std::string("@data"), l);

  Expression start2 = c.make_node<Integer>(5UL, l);
  Expression end2 = c.make_node<Integer>(15UL, l);
  auto *range2 = c.make_node<Range>(std::move(start2), std::move(end2), l);

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
    auto *cloned = clone(this->ctx, nodes[i], nullptr);
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
