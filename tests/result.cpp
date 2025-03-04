#include "util/result.h"
#include "gtest/gtest.h"

namespace bpftrace::test::result {

class NotOK : public ErrorInfo<NotOK> {
public:
  static char ID;
  void log(llvm::raw_ostream &OS) const override
  {
    OS << "Not OK.";
  }
};

class ReallyNotOK : public ErrorInfo<ReallyNotOK> {
public:
  static char ID;
  void log(llvm::raw_ostream &OS) const override
  {
    OS << "Really not OK.";
  }
};

char NotOK::ID;
char ReallyNotOK::ID;

static Result<> alwaysOK()
{
  return OK();
}

static Result<> alwaysNotOK()
{
  return make_error<NotOK>();
}

static Result<bool> maybeOK(bool ok, bool really_bad)
{
  if (!ok) {
    if (really_bad)
      return make_error<ReallyNotOK>();
    return make_error<NotOK>();
  }
  return really_bad; // Arbitrary value.
}

TEST(result, okay)
{
  auto ok = alwaysOK();
  EXPECT_TRUE(bool(ok));
}

TEST(result, not_okay)
{
  auto ok = alwaysNotOK();
  EXPECT_FALSE(bool(ok));
}

TEST(result, values)
{
  auto ok = maybeOK(true, false);
  EXPECT_TRUE(bool(ok));
  EXPECT_FALSE(*ok);
  ok = maybeOK(true, true);
  EXPECT_TRUE(bool(ok));
  EXPECT_TRUE(*ok);
}

TEST(result, handle_err_found)
{
  auto ok = maybeOK(false, false);
  if (!ok) {
    auto nowOk = handleErrors(std::move(ok), [](const NotOK &) {});
    EXPECT_TRUE(bool(nowOk)); // Should now be fine.
  }
}

TEST(result, handle_err_missing)
{
  auto ok = maybeOK(false, true);
  if (!ok) {
    auto nowOk = handleErrors(std::move(ok), [](const NotOK &) {});
    EXPECT_FALSE(bool(nowOk)); // Should still have an error.
  }
}

TEST(result, handle_inline)
{
  auto ok = handleErrors(maybeOK(true, false), [](const NotOK &) {});
  EXPECT_TRUE(bool(ok)); // Handled above.
}

} // namespace bpftrace::test::result
