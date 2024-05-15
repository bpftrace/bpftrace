#include "ast/passes/collect_nodes.h"
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
  auto &var = *new Variable{ "myvar", bpftrace::location{} };

  CollectNodes<Variable> visitor;
  visitor.run(var);

  test({ var }, visitor.nodes());
}

TEST(CollectNodes, indirect)
{
  auto &var = *new Variable{ "myvar", bpftrace::location{} };
  auto &unop = *new Unop{ Operator::INCREMENT, &var, bpftrace::location{} };

  CollectNodes<Variable> visitor;
  visitor.run(unop);

  test({ var }, visitor.nodes());
}

TEST(CollectNodes, none)
{
  auto &map = *new Map{ "myvar", bpftrace::location{} };
  auto &unop = *new Unop{ Operator::INCREMENT, &map, bpftrace::location{} };

  CollectNodes<Variable> visitor;
  visitor.run(unop);

  test({}, visitor.nodes());
}

TEST(CollectNodes, multiple_runs)
{
  auto &var1 = *new Variable{ "myvar1", bpftrace::location{} };
  auto &unop1 = *new Unop{ Operator::INCREMENT, &var1, bpftrace::location{} };

  auto &var2 = *new Variable{ "myvar2", bpftrace::location{} };
  auto &unop2 = *new Unop{ Operator::INCREMENT, &var2, bpftrace::location{} };

  CollectNodes<Variable> visitor;
  visitor.run(unop1);
  visitor.run(unop2);

  test({ var1, var2 }, visitor.nodes());
}

TEST(CollectNodes, multiple_children)
{
  auto &var1 = *new Variable{ "myvar1", bpftrace::location{} };
  auto &var2 = *new Variable{ "myvar2", bpftrace::location{} };

  auto &binop = *new Binop{
    &var1, Operator::PLUS, &var2, bpftrace::location{}
  };

  CollectNodes<Variable> visitor;
  visitor.run(binop);

  test({ var1, var2 }, visitor.nodes());
}

TEST(CollectNodes, predicate)
{
  auto &var1 = *new Variable{ "myvar1", bpftrace::location{} };
  auto &var2 = *new Variable{ "myvar2", bpftrace::location{} };

  auto &binop = *new Binop{
    &var1, Operator::PLUS, &var2, bpftrace::location{}
  };

  CollectNodes<Variable> visitor;
  visitor.run(binop, [](const auto &var) { return var.ident == "myvar2"; });

  test({ var2 }, visitor.nodes());
}

TEST(CollectNodes, nested)
{
  auto &var1 = *new Variable{ "myvar1", bpftrace::location{} };
  auto &var2 = *new Variable{ "myvar2", bpftrace::location{} };
  auto &var3 = *new Variable{ "myvar3", bpftrace::location{} };

  auto &binop1 = *new Binop{
    &var1, Operator::PLUS, &var2, bpftrace::location{}
  };
  auto &binop2 = *new Binop{
    &binop1, Operator::MINUS, &var3, bpftrace::location{}
  };

  CollectNodes<Binop> visitor;
  visitor.run(binop2,
              [](const auto &binop) { return binop.op == Operator::PLUS; });

  test({ binop1 }, visitor.nodes());
}

} // namespace bpftrace::test::collect_nodes
