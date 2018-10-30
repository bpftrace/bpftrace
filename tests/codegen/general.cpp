#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "semantic_analyser.h"

namespace bpftrace {
namespace test {
namespace codegen {

using ::testing::_;

class MockBPFtrace : public BPFtrace {
public:
  MOCK_METHOD1(add_probe, int(ast::Probe &p));
};

TEST(codegen, populate_sections)
{
  BPFtrace bpftrace;
  Driver driver;

  ASSERT_EQ(driver.parse_str("kprobe:foo { 1 } kprobe:bar { 1 }"), 0);
  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);
  std::stringstream out;
  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  auto bpforc = codegen.compile();

  // Check sections are populated
  EXPECT_EQ(bpforc->sections_.size(), 2);
  EXPECT_EQ(bpforc->sections_.count("s_kprobe:foo_1"), 1);
  EXPECT_EQ(bpforc->sections_.count("s_kprobe:bar_1"), 1);
}

TEST(codegen, printf_offsets)
{
  BPFtrace bpftrace;
  Driver driver;

  // TODO (mmarchini): also test printf with a string argument
  ASSERT_EQ(driver.parse_str("struct Foo { char c; int i; } kprobe:f { $foo = (Foo*)0; printf(\"%c %u\\n\", $foo->c, $foo->i) }"), 0);
  ClangParser clang;
  clang.parse(driver.root_, bpftrace.structs_);
  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);
  ASSERT_EQ(semantics.create_maps(true), 0);
  std::stringstream out;
  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  auto bpforc = codegen.compile();

  EXPECT_EQ(bpftrace.printf_args_.size(), 1);
  auto &fmt = std::get<0>(bpftrace.printf_args_[0]);
  auto &args = std::get<1>(bpftrace.printf_args_[0]);

  EXPECT_EQ(fmt, "%c %u\n");

  EXPECT_EQ(args.size(), 2);

  // NOTE (mmarchini) type.size is the original arg size, and it might be
  // different from the actual size we use to store in memory
  EXPECT_EQ(args[0].type.type, Type::integer);
  EXPECT_EQ(args[0].type.size, 8);
  EXPECT_EQ(args[0].offset, 8);

  EXPECT_EQ(args[1].type.type, Type::integer);
  EXPECT_EQ(args[1].type.size, 8);
  EXPECT_EQ(args[1].offset, 16);
}

TEST(codegen, probe_count)
{
  MockBPFtrace bpftrace;
  EXPECT_CALL(bpftrace, add_probe(_)).Times(2);

  Driver driver;

  ASSERT_EQ(driver.parse_str("kprobe:f { 1; } kprobe:d { 1; }"), 0);
  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);
  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  codegen.compile();
}
} // namespace codegen
} // namespace test
} // namespace bpftrace
