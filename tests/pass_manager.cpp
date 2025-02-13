#include "ast/pass_manager.h"
#include "ast/location.h"
#include "util/result.h"
#include "gtest/gtest.h"

using bpftrace::ast::Pass;
using bpftrace::ast::PassManager;

namespace bpftrace::test::passes {

class Error1 : public ErrorInfo<Error1> {
public:
  static char ID;
  void log(llvm::raw_ostream &) const override
  {
  }
};

class Error2 : public ErrorInfo<Error2> {
public:
  static char ID;
  void log(llvm::raw_ostream &) const override
  {
  }
};

char Error1::ID;
char Error2::ID;

Pass CreateTest1Pass(bool error = false)
{
  return Pass::create("test1", [error]() -> Result<> {
    if (error) {
      return make_error<Error1>();
    }
    return OK();
  });
}

class Test2Output : public ast::State<"test2output"> {};

Pass CreateTest2Pass(bool error = false)
{
  return Pass::create("test2", [error]() -> Result<Test2Output> {
    if (error) {
      return make_error<Error2>();
    }
    return Test2Output();
  });
}

class Test3Output : public ast::State<"test3output"> {};

Pass CreateTest3Pass()
{
  return Pass::create("test3", [](Test2Output &) -> Result<Test3Output> {
    return Test3Output();
  });
}

TEST(PassManager, noop_pass)
{
  PassManager pm;
  pm.add(Pass::create("void", []() {}));
  EXPECT_TRUE(bool(pm.run()));
}

TEST(PassManager, single_pass)
{
  PassManager pm;
  pm.add(CreateTest1Pass());
  EXPECT_TRUE(bool(pm.run()));
}

TEST(PassManager, single_pass_with_output)
{
  PassManager pm;
  pm.add(CreateTest2Pass());
  auto out = pm.run();
  EXPECT_TRUE(bool(out));
  out->get<Test2Output>();                   // Should work.
  EXPECT_DEATH(out->get<Test3Output>(), ""); // Should die.
}

TEST(PassManager, single_pass_with_error)
{
  PassManager pm;
  pm.add(CreateTest1Pass(true));
  auto out = pm.run();
  EXPECT_FALSE(bool(out));
  EXPECT_TRUE(bool(handleErrors(std::move(out), [](const Error1 &) {})));
}

TEST(PassManager, multiple_passes)
{
  PassManager pm;
  pm.add(CreateTest1Pass());
  pm.add(CreateTest1Pass());
  EXPECT_TRUE(bool(pm.run()));
}

TEST(PassManager, multiple_passes_with_dependencies)
{
  PassManager pm;
  pm.add(CreateTest2Pass());
  pm.add(CreateTest3Pass());
  EXPECT_TRUE(bool(pm.run()));
}

TEST(PassManager, multiple_passes_with_bad_dependencies)
{
  PassManager pm;
  pm.add(CreateTest1Pass());
  EXPECT_DEATH(pm.add(CreateTest3Pass()), ""); // Should assert fail.
}

TEST(PassManager, multiple_passes_with_partial_success)
{
  PassManager pm;
  pm.add(CreateTest1Pass());
  pm.add(CreateTest2Pass(true));
  auto out = pm.run();
  EXPECT_FALSE(bool(out));
  EXPECT_TRUE(bool(handleErrors(std::move(out), [](const Error2 &) {})));
}

TEST(PassManager, multiple_passes_complex)
{
  PassManager pm;
  pm.add(CreateTest1Pass());
  pm.add(CreateTest2Pass());
  pm.add(CreateTest1Pass());
  pm.add(CreateTest3Pass());
  EXPECT_TRUE(bool(pm.run()));
}

} // namespace bpftrace::test::passes
