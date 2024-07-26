#include "common.h"

#include <iterator>

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_ustack)
{
  auto result = NAME;

  test("kprobe:f { @x = ustack(); @y = ustack(6); @z = ustack(perf) }", result);
}

TEST(codegen, call_ustack_mapids)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);

  ASSERT_EQ(driver.parse_str(
                "kprobe:f { @x = ustack(5); @y = ustack(6); @z = ustack(6) }"),
            0);

  ClangParser clang;
  clang.parse(driver.ctx.root, *bpftrace);

  // Override to mockbpffeature.
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.ctx, *bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);

  ast::ResourceAnalyser resource_analyser(driver.ctx.root, *bpftrace);
  auto resources_optional = resource_analyser.analyse();
  ASSERT_TRUE(resources_optional.has_value());
  bpftrace->resources = resources_optional.value();

  ast::CodegenLLVM codegen(driver.ctx.root, *bpftrace);
  bpftrace->bytecode_ = codegen.compile();

  ASSERT_EQ(bpftrace->bytecode_.maps().size(), 8);
  ASSERT_EQ(bpftrace->bytecode_.countStackMaps(), 3U);

  StackType stack_type;
  stack_type.limit = 5;
  ASSERT_TRUE(bpftrace->bytecode_.hasMap(stack_type));
  stack_type.limit = 6;
  ASSERT_TRUE(bpftrace->bytecode_.hasMap(stack_type));
}

TEST(codegen, call_ustack_modes_mapids)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);

  ASSERT_EQ(driver.parse_str(
                "kprobe:f { @w = ustack(raw); @x = ustack(perf); @y = "
                "ustack(bpftrace); @z = ustack() }"),
            0);

  ClangParser clang;
  clang.parse(driver.ctx.root, *bpftrace);

  // Override to mockbpffeature.
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.ctx, *bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);

  ast::ResourceAnalyser resource_analyser(driver.ctx.root, *bpftrace);
  auto resources_optional = resource_analyser.analyse();
  ASSERT_TRUE(resources_optional.has_value());
  bpftrace->resources = resources_optional.value();

  ast::CodegenLLVM codegen(driver.ctx.root, *bpftrace);
  bpftrace->bytecode_ = codegen.compile();

  ASSERT_EQ(bpftrace->bytecode_.maps().size(), 10);
  ASSERT_EQ(bpftrace->bytecode_.countStackMaps(), 4U);

  StackType stack_type;
  stack_type.mode = StackMode::perf;
  ASSERT_TRUE(bpftrace->bytecode_.hasMap(stack_type));
  stack_type.mode = StackMode::bpftrace;
  ASSERT_TRUE(bpftrace->bytecode_.hasMap(stack_type));
  stack_type.mode = StackMode::raw;
  ASSERT_TRUE(bpftrace->bytecode_.hasMap(stack_type));
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
