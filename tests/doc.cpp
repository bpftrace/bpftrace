#include "doc.h"

#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "bpftrace.h"
#include "parser.h"

namespace bpftrace::test {
namespace {

std::vector<doc::Entry> parse_docs(const std::string &input)
{
  BPFtrace bpftrace;
  ast::ASTContext ast("stdin", input);
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .run();
  EXPECT_TRUE(bool(ok));
  if (!ok) {
    return {};
  }

  std::ostringstream out;
  ast.diagnostics().emit(out);
  EXPECT_TRUE(ast.diagnostics().ok()) << out.str();
  if (!ast.diagnostics().ok()) {
    return {};
  }
  return doc::extract(ast);
}

TEST(Doc, extracts_helpers_from_comment_blocks)
{
  const auto entries = parse_docs(R"(
// :variant void assert(bool condition, string message)
// Assert that the condition is true.
macro assert(cond, msg)
{
  1
}

// :function bswap
// :variant uint32 bswap(uint32 n)
// Reverse the byte order of an integer.
//
// :variant uint64 cgroup()
// Resolve the current cgroup identifier.
macro cgroup()
{
  1
}
)");

  ASSERT_EQ(entries.size(), 3ul);

  EXPECT_EQ(entries.at(0).name, "assert");
  EXPECT_EQ(entries.at(0).kind, doc::Kind::Macro);
  EXPECT_THAT(
      entries.at(0).variants,
      testing::ElementsAre("void assert(bool condition, string message)"));

  EXPECT_EQ(entries.at(1).name, "bswap");
  EXPECT_EQ(entries.at(1).kind, doc::Kind::Function);
  EXPECT_THAT(entries.at(1).variants,
              testing::ElementsAre("uint32 bswap(uint32 n)"));

  EXPECT_EQ(entries.at(2).name, "cgroup");
  EXPECT_EQ(entries.at(2).kind, doc::Kind::Macro);
  EXPECT_THAT(entries.at(2).variants,
              testing::ElementsAre("uint64 cgroup()", "uint64 cgroup"));
}

TEST(Doc, extracts_probe_documentation)
{
  const auto entries = parse_docs(R"(
// Report a simple probe hit.
kprobe:f
{
  1
}
)");

  ASSERT_EQ(entries.size(), 1ul);
  EXPECT_EQ(entries.at(0).name, "kprobe:f");
  EXPECT_EQ(entries.at(0).kind, doc::Kind::Probe);
  EXPECT_EQ(entries.at(0).description, "Report a simple probe hit.");
}

} // namespace
} // namespace bpftrace::test
