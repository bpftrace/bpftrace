#include "common.h"

#include <iterator>

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_ustack)
{
  auto result = NAME;

  // Mode doesn't directly affect codegen, so both should generate the same
  // program
  test("kprobe:f { @x = ustack(); @y = ustack(6) }", result);
  test("kprobe:f { @x = ustack(perf); @y = ustack(perf, 6) }", result);
  test("kprobe:f { @x = ustack(perf); @y = ustack(bpftrace) }", result);
}

TEST(codegen, call_ustack_mapids)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);

  ASSERT_EQ(driver.parse_str(
                "kprobe:f { @x = ustack(5); @y = ustack(6); @z = ustack(6) }"),
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
  codegen.compile();

  ASSERT_EQ(std::distance(bpftrace->maps.begin(), bpftrace->maps.end()), 6);
  ASSERT_EQ(bpftrace->maps.CountStackTypes(), 2U);

  StackType stack_type;
  stack_type.limit = 5;
  ASSERT_TRUE(bpftrace->maps.Has(stack_type));
  stack_type.limit = 6;
  ASSERT_TRUE(bpftrace->maps.Has(stack_type));
}

TEST(codegen, call_ustack_modes_mapids)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);

  ASSERT_EQ(driver.parse_str("kprobe:f { @x = ustack(perf); @y = "
                             "ustack(bpftrace); @z = ustack() }"),
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
  codegen.compile();

  ASSERT_EQ(std::distance(bpftrace->maps.begin(), bpftrace->maps.end()), 6);
  ASSERT_EQ(bpftrace->maps.CountStackTypes(), 2U);

  StackType stack_type;
  stack_type.mode = StackMode::perf;
  ASSERT_TRUE(bpftrace->maps.Has(stack_type));
  stack_type.mode = StackMode::bpftrace;
  ASSERT_TRUE(bpftrace->maps.Has(stack_type));
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
