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
  void log(llvm::raw_ostream & /*OS*/) const override
  {
  }
};

class Error2 : public ErrorInfo<Error2> {
public:
  static char ID;
  void log(llvm::raw_ostream & /*OS*/) const override
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

class A;

class B : public ast::State<"B"> {
public:
  B(A &a);
  ~B() override
  {
    EXPECT_EQ(*ptr, true);
  }

private:
  std::shared_ptr<bool> ptr;
};

class A : public ast::State<"A"> {
public:
  ~A() override
  {
    for (auto &callback : callbacks) {
      callback();
    }
  }
  std::vector<std::function<void()>> callbacks;
};

B::B(A &a) : ptr(std::make_shared<bool>(true))
{
  a.callbacks.emplace_back([ptr = this->ptr] { *ptr = false; });
}

class C : public ast::State<"C"> {
public:
  C(A &a) : b_(a) {};

private:
  B b_;
};

TEST(PassManager, teardown_ordering)
{
  PassManager pm;
  pm.add(Pass::create("a", []() { return A(); }));
  pm.add(Pass::create("b", [](A &a) { return B(a); }));
  pm.add(Pass::create("c", [](A &a) { return C(a); }));
  EXPECT_TRUE(bool(pm.run())); // Context discarded.
}

} // namespace bpftrace::test::passes
