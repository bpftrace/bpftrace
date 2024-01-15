#include "bpfbytecode.h"
#include "driver.h"
#include "mocks.h"
#include "passes/codegen_llvm.h"
#include "passes/semantic_analyser.h"

#include "gtest/gtest.h"

namespace bpftrace {
namespace test {
namespace bpfbytecode {

BpfBytecode codegen(const std::string &input)
{
  auto bpftrace = get_mock_bpftrace();

  Driver driver(*bpftrace);
  EXPECT_EQ(driver.parse_str(input), 0);

  ast::SemanticAnalyser semantics(driver.root.get(), *bpftrace);
  EXPECT_EQ(semantics.analyse(), 0);

  ast::CodegenLLVM codegen(driver.root.get(), *bpftrace);
  return codegen.compile();
}

TEST(bpfbytecode, populate_sections)
{
  auto bytecode = codegen("kprobe:foo { 1 } kprobe:bar { 1 }");

  EXPECT_TRUE(bytecode.hasSection("s_kprobe:foo_1"));
  EXPECT_TRUE(bytecode.hasSection("s_kprobe:bar_2"));
}

} // namespace bpfbytecode
} // namespace test
} // namespace bpftrace
