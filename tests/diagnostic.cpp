#include "ast/diagnostic.h"
#include "log.h"
#include "gtest/gtest.h"

namespace bpftrace::test::diagnostic {

TEST(Diagnostics, WarningSilencing)
{
  ast::Diagnostics diags;
  auto &warn = diags.addWarning(ast::Location());
  warn << "This is a warning";
  warn.addHint() << "This is a hint";

  // When warnings are enabled
  {
    std::stringstream out;
    diags.emit(out);
    EXPECT_TRUE(out.str().find("WARNING: This is a warning") !=
                std::string::npos);
    EXPECT_TRUE(out.str().find("HINT: This is a hint") != std::string::npos);
  }

  // When warnings are disabled
  {
    DISABLE_LOG(WARNING);
    std::stringstream out;
    diags.emit(out);
    EXPECT_TRUE(out.str().find("WARNING: This is a warning") ==
                std::string::npos);
    EXPECT_TRUE(out.str().find("HINT: This is a hint") == std::string::npos);
    ENABLE_LOG(WARNING);
  }
}

TEST(Diagnostics, ErrorNotSilenced)
{
  ast::Diagnostics diags;
  auto &err = diags.addError(ast::Location());
  err << "This is an error";
  err.addHint() << "This is an error hint";

  // When warnings are disabled, errors and their hints should still be shown
  {
    DISABLE_LOG(WARNING);
    std::stringstream out;
    diags.emit(out);
    EXPECT_TRUE(out.str().find("ERROR: This is an error") != std::string::npos);
    EXPECT_TRUE(out.str().find("HINT: This is an error hint") !=
                std::string::npos);
    ENABLE_LOG(WARNING);
  }
}

} // namespace bpftrace::test::diagnostic
