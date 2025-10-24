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
  auto &var = *ctx.make_node<Variable>(Location(), "myvar");

  CollectNodes<Variable> visitor;
  visitor.visit(var);

  test({ var }, visitor.nodes());
}

TEST(CollectNodes, indirect)
{
  ASTContext ctx;
  auto &var = *ctx.make_node<Variable>(Location(), "myvar");
  auto &unop = *ctx.make_node<Unop>(Location(), &var, Operator::PRE_INCREMENT);

  CollectNodes<Variable> visitor;
  visitor.visit(unop);

  test({ var }, visitor.nodes());
}

TEST(CollectNodes, none)
{
  ASTContext ctx;
  auto &map = *ctx.make_node<Map>(Location(), "myvar");
  auto &unop = *ctx.make_node<Unop>(Location(), &map, Operator::PRE_INCREMENT);

  CollectNodes<Variable> visitor;
  visitor.visit(unop);

  test({}, visitor.nodes());
}

TEST(CollectNodes, multiple_runs)
{
  ASTContext ctx;
  auto &var1 = *ctx.make_node<Variable>(Location(), "myvar1");
  auto &unop1 = *ctx.make_node<Unop>(Location(),
                                     &var1,
                                     Operator::PRE_INCREMENT);

  auto &var2 = *ctx.make_node<Variable>(Location(), "myvar2");
  auto &unop2 = *ctx.make_node<Unop>(Location(),
                                     &var2,
                                     Operator::PRE_INCREMENT);

  CollectNodes<Variable> visitor;
  visitor.visit(unop1);
  visitor.visit(unop2);

  test({ var1, var2 }, visitor.nodes());
}

TEST(CollectNodes, multiple_children)
{
  ASTContext ctx;
  auto &var1 = *ctx.make_node<Variable>(Location(), "myvar1");
  auto &var2 = *ctx.make_node<Variable>(Location(), "myvar2");
  auto &binop = *ctx.make_node<Binop>(Location(), &var1, Operator::PLUS, &var2);

  CollectNodes<Variable> visitor;
  visitor.visit(binop);

  test({ var1, var2 }, visitor.nodes());
}

TEST(CollectNodes, predicate)
{
  ASTContext ctx;
  auto &var1 = *ctx.make_node<Variable>(Location(), "myvar1");
  auto &var2 = *ctx.make_node<Variable>(Location(), "myvar2");
  auto &binop = *ctx.make_node<Binop>(Location(), &var1, Operator::PLUS, &var2);

  CollectNodes<Variable> visitor;
  visitor.visit(binop, [](const auto &var) { return var.ident == "myvar2"; });

  test({ var2 }, visitor.nodes());
}

TEST(CollectNodes, nested)
{
  ASTContext ctx;
  auto &var1 = *ctx.make_node<Variable>(Location(), "myvar1");
  auto &var2 = *ctx.make_node<Variable>(Location(), "myvar2");
  auto &var3 = *ctx.make_node<Variable>(Location(), "myvar3");
  auto &binop1 = *ctx.make_node<Binop>(
      Location(), &var1, Operator::PLUS, &var2);
  auto &binop2 = *ctx.make_node<Binop>(
      Location(), &binop1, Operator::MINUS, &var3);

  CollectNodes<Binop> visitor;
  visitor.visit(binop2,
                [](const auto &binop) { return binop.op == Operator::PLUS; });

  test({ binop1 }, visitor.nodes());
}

} // namespace bpftrace::test::collect_nodes
