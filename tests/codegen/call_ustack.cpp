#include "common.h"

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
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  FakeMap::next_mapfd_ = 1;

  ASSERT_EQ(driver.parse_str(
                "kprobe:f { @x = ustack(5); @y = ustack(6); @z = ustack(6) }"),
            0);

  ClangParser clang;
  clang.parse(driver.root(), bpftrace);

  // Override to mockbpffeature.
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.root(), bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);
  ASSERT_EQ(semantics.create_maps(true), 0);

  ast::CodegenLLVM codegen(driver.root(), bpftrace);
  codegen.compile();

  ASSERT_EQ(FakeMap::next_mapfd_, 7);
  ASSERT_EQ(bpftrace.maps.CountStackTypes(), 2U);

  StackType stack_type;
  stack_type.limit = 5;
  ASSERT_TRUE(bpftrace.maps.Has(stack_type));
  stack_type.limit = 6;
  ASSERT_TRUE(bpftrace.maps.Has(stack_type));
}

TEST(codegen, call_ustack_modes_mapids)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  FakeMap::next_mapfd_ = 1;

  ASSERT_EQ(driver.parse_str("kprobe:f { @x = ustack(perf); @y = "
                             "ustack(bpftrace); @z = ustack() }"),
            0);

  ClangParser clang;
  clang.parse(driver.root(), bpftrace);

  // Override to mockbpffeature.
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.root(), bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);
  ASSERT_EQ(semantics.create_maps(true), 0);

  ast::CodegenLLVM codegen(driver.root(), bpftrace);
  codegen.compile();

  ASSERT_EQ(FakeMap::next_mapfd_, 7);
  ASSERT_EQ(bpftrace.maps.CountStackTypes(), 2U);

  StackType stack_type;
  stack_type.mode = StackMode::perf;
  ASSERT_TRUE(bpftrace.maps.Has(stack_type));
  stack_type.mode = StackMode::bpftrace;
  ASSERT_TRUE(bpftrace.maps.Has(stack_type));
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
