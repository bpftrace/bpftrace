#include "ast/passes/collect_nodes.h"
#include "ast/context.h"
#include "gtest/gtest.h"

#include <functional>
#include <vector>

namespace bpftrace::test::collect_nodes {

using namespace bpftrace::ast;

template <typename T>
void test(const std::vector<std::reference_wrapper<T>> &expected,
          const std::vector<std::reference_wrapper<T>> &actual)
{
  ASSERT_EQ(expected.size(), actual.size());
  for (size_t i = 0; i < expected.size(); i++) {
    EXPECT_EQ(&expected[i].get(), &actual[i].get());
  }
}

TEST(CollectNodes, direct)
{
  ASTContext ctx;
  auto &var = *ctx.make_node<Variable>("myvar", Location());

  CollectNodes<Variable> visitor;
  visitor.visit(var);

  test({ var }, visitor.nodes());
}

TEST(CollectNodes, indirect)
{
  ASTContext ctx;
  auto &var = *ctx.make_node<Variable>("myvar", Location());
  auto &unop = *ctx.make_node<Unop>(&var, Operator::PRE_INCREMENT, Location());

  CollectNodes<Variable> visitor;
  visitor.visit(unop);

  test({ var }, visitor.nodes());
}

TEST(CollectNodes, none)
{
  ASTContext ctx;
  auto &map = *ctx.make_node<Map>("myvar", Location());
  auto &unop = *ctx.make_node<Unop>(&map, Operator::PRE_INCREMENT, Location());

  CollectNodes<Variable> visitor;
  visitor.visit(unop);

  test({}, visitor.nodes());
}

TEST(CollectNodes, multiple_runs)
{
  ASTContext ctx;
  auto &var1 = *ctx.make_node<Variable>("myvar1", Location());
  auto &unop1 = *ctx.make_node<Unop>(&var1,
                                     Operator::PRE_INCREMENT,
                                     Location());

  auto &var2 = *ctx.make_node<Variable>("myvar2", Location());
  auto &unop2 = *ctx.make_node<Unop>(&var2,
                                     Operator::PRE_INCREMENT,
                                     Location());

  CollectNodes<Variable> visitor;
  visitor.visit(unop1);
  visitor.visit(unop2);

  test({ var1, var2 }, visitor.nodes());
}

TEST(CollectNodes, multiple_children)
{
  ASTContext ctx;
  auto &var1 = *ctx.make_node<Variable>("myvar1", Location());
  auto &var2 = *ctx.make_node<Variable>("myvar2", Location());
  auto &binop = *ctx.make_node<Binop>(&var1, Operator::PLUS, &var2, Location());

  CollectNodes<Variable> visitor;
  visitor.visit(binop);

  test({ var1, var2 }, visitor.nodes());
}

TEST(CollectNodes, predicate)
{
  ASTContext ctx;
  auto &var1 = *ctx.make_node<Variable>("myvar1", Location());
  auto &var2 = *ctx.make_node<Variable>("myvar2", Location());
  auto &binop = *ctx.make_node<Binop>(&var1, Operator::PLUS, &var2, Location());

  CollectNodes<Variable> visitor;
  visitor.visit(binop, [](const auto &var) { return var.ident == "myvar2"; });

  test({ var2 }, visitor.nodes());
}

TEST(CollectNodes, nested)
{
  ASTContext ctx;
  auto &var1 = *ctx.make_node<Variable>("myvar1", Location());
  auto &var2 = *ctx.make_node<Variable>("myvar2", Location());
  auto &var3 = *ctx.make_node<Variable>("myvar3", Location());
  auto &binop1 = *ctx.make_node<Binop>(
      &var1, Operator::PLUS, &var2, Location());
  auto &binop2 = *ctx.make_node<Binop>(
      &binop1, Operator::MINUS, &var3, Location());

  CollectNodes<Binop> visitor;
  visitor.visit(binop2,
                [](const auto &binop) { return binop.op == Operator::PLUS; });

  test({ binop1 }, visitor.nodes());
}

} // namespace bpftrace::test::collect_nodes
