#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "ast/semantic_analyser.h"
#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"

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

  bool is_traceable_func(
      const std::string &__attribute__((unused))) const override
  {
    return true;
  }
};

TEST(codegen, populate_sections)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);

  ASSERT_EQ(driver.parse_str("kprobe:foo { 1 } kprobe:bar { 1 }"), 0);
  // Override to mockbpffeature.
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.root_, *bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);
  ast::CodegenLLVM codegen(driver.root_, *bpftrace);
  auto bpforc = codegen.compile();

  EXPECT_TRUE(bpforc->getSection("s_kprobe:foo_1").has_value());
  EXPECT_TRUE(bpforc->getSection("s_kprobe:bar_1").has_value());
}

TEST(codegen, printf_offsets)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);

  ASSERT_EQ(driver.parse_str(
                "struct Foo { char c; int i; char str[10]; }\n"
                "kprobe:f\n"
                "{\n"
                "  $foo = (struct Foo*)arg0;\n"
                "  printf(\"%c %u %s %p\\n\", $foo->c, $foo->i, $foo->str, 0)\n"
                "}"),
            0);
  ClangParser clang;
  clang.parse(driver.root_, *bpftrace);

  // Override to mockbpffeature.
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.root_, *bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);

  ast::ResourceAnalyser resource_analyser(driver.root_);
  auto resources = resource_analyser.analyse();
  ASSERT_EQ(resources.create_maps(*bpftrace, true), 0);
  bpftrace->resources = resources;

  ast::CodegenLLVM codegen(driver.root_, *bpftrace);
  codegen.generate_ir();

  EXPECT_EQ(resources.printf_args.size(), 1U);
  auto &fmt = std::get<0>(bpftrace->resources.printf_args[0]);
  auto &args = std::get<1>(bpftrace->resources.printf_args[0]);

  EXPECT_EQ(fmt, "%c %u %s %p\n");

  EXPECT_EQ(args.size(), 4U);

  // Note that scalar types are promoted to 64-bits when put into
  // a perf event buffer
  EXPECT_EQ(args[0].type.type, Type::integer);
  EXPECT_EQ(args[0].type.GetSize(), 8U);
  EXPECT_EQ(args[0].offset, 8);

  EXPECT_EQ(args[1].type.type, Type::integer);
  EXPECT_EQ(args[1].type.GetSize(), 8U);
  EXPECT_EQ(args[1].offset, 16);

  EXPECT_EQ(args[2].type.type, Type::string);
  EXPECT_EQ(args[2].type.GetSize(), 10U);
  EXPECT_EQ(args[2].offset, 24);

  EXPECT_EQ(args[3].type.type, Type::integer);
  EXPECT_EQ(args[3].type.GetSize(), 8U);
  EXPECT_EQ(args[3].offset, 40);
}

TEST(codegen, probe_count)
{
  MockBPFtrace bpftrace;
  EXPECT_CALL(bpftrace, add_probe(_)).Times(2);

  Driver driver(bpftrace);

  ASSERT_EQ(driver.parse_str("kprobe:f { 1; } kprobe:d { 1; }"), 0);
  // Override to mockbpffeature.
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);
  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  codegen.generate_ir();
}
} // namespace codegen
} // namespace test
} // namespace bpftrace
