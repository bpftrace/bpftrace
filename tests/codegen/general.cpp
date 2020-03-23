#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "semantic_analyser.h"

#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

using ::testing::_;

class MockBPFtrace : public BPFtrace
{
public:
#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Winconsistent-missing-override"
#endif
  MOCK_METHOD1(add_probe, int(ast::Probe &p));
#pragma GCC diagnostic pop

  int resolve_uname(const std::string &name,
                    struct symbol *sym,
                    const std::string &path) const override
  {
    (void)path;
    sym->name = name;
    sym->address = 12345;
    sym->size = 4;
    return 0;
  }
};

TEST(codegen, populate_sections)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);

  ASSERT_EQ(driver.parse_str("kprobe:foo { 1 } kprobe:bar { 1 }"), 0);
  MockBPFfeature feature;
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, feature);
  ASSERT_EQ(semantics.analyse(), 0);
  std::stringstream out;
  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  auto bpforc = codegen.compile();

  // Check sections are populated
  EXPECT_EQ(bpforc->sections_.size(), 2U);
  EXPECT_EQ(bpforc->sections_.count("s_kprobe:foo_1"), 1U);
  EXPECT_EQ(bpforc->sections_.count("s_kprobe:bar_1"), 1U);
}

TEST(codegen, printf_offsets)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);

  ASSERT_EQ(driver.parse_str(
                "struct Foo { char c; int i; char str[10]; }\n"
                "kprobe:f\n"
                "{\n"
                "  $foo = (struct Foo*)0;\n"
                "  printf(\"%c %u %s %p\\n\", $foo->c, $foo->i, $foo->str, 0)\n"
                "}"),
            0);
  ClangParser clang;
  clang.parse(driver.root_, bpftrace);
  MockBPFfeature feature;
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, feature);
  ASSERT_EQ(semantics.analyse(), 0);
  ASSERT_EQ(semantics.create_maps(true), 0);
  std::stringstream out;
  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  auto bpforc = codegen.compile();

  EXPECT_EQ(bpftrace.printf_args_.size(), 1U);
  auto &fmt = std::get<0>(bpftrace.printf_args_[0]);
  auto &args = std::get<1>(bpftrace.printf_args_[0]);

  EXPECT_EQ(fmt, "%c %u %s %p\n");

  EXPECT_EQ(args.size(), 4U);

  // Note that scalar types are promoted to 64-bits when put into
  // a perf event buffer
  EXPECT_EQ(args[0].type.type, Type::integer);
  EXPECT_EQ(args[0].type.size, 8U);
  EXPECT_EQ(args[0].offset, 8);

  EXPECT_EQ(args[1].type.type, Type::integer);
  EXPECT_EQ(args[1].type.size, 8U);
  EXPECT_EQ(args[1].offset, 16);

  EXPECT_EQ(args[2].type.type, Type::string);
  EXPECT_EQ(args[2].type.size, 10U);
  EXPECT_EQ(args[2].offset, 24);

  EXPECT_EQ(args[3].type.type, Type::integer);
  EXPECT_EQ(args[3].type.size, 8U);
  EXPECT_EQ(args[3].offset, 40);
}

TEST(codegen, probe_count)
{
  MockBPFtrace bpftrace;
  EXPECT_CALL(bpftrace, add_probe(_)).Times(2);

  Driver driver(bpftrace);

  ASSERT_EQ(driver.parse_str("kprobe:f { 1; } kprobe:d { 1; }"), 0);
  MockBPFfeature feature;
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, feature);
  ASSERT_EQ(semantics.analyse(), 0);
  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  codegen.compile();
}
} // namespace codegen
} // namespace test
} // namespace bpftrace
