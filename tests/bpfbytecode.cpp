#include "bpfbytecode.h"
#include "driver.h"
#include "mocks.h"
#include "passes/codegen_llvm.h"
#include "passes/semantic_analyser.h"

#include "gtest/gtest.h"

namespace bpftrace {
namespace test {
namespace bpfbytecode {

BpfBytecode codegen(std::string_view input)
{
  auto bpftrace = get_mock_bpftrace();

  Driver driver(*bpftrace);
  EXPECT_EQ(driver.parse_str(input), 0);

  ast::SemanticAnalyser semantics(driver.ctx, *bpftrace);
  EXPECT_EQ(semantics.analyse(), 0);

  ast::CodegenLLVM codegen(driver.ctx.root, *bpftrace);
  return codegen.compile();
}

TEST(bpfbytecode, create_programs)
{
  auto bytecode = codegen("kprobe:foo { 1 }");

  Probe foo;
  foo.type = ProbeType::kprobe;
  foo.name = "kprobe:foo";
  foo.index = 1;

  auto &program = bytecode.getProgramForProbe(foo);

  EXPECT_EQ(std::string_view{ bpf_program__name(program.bpf_prog()) },
            "kprobe_foo_1");
  EXPECT_EQ(std::string_view{ bpf_program__section_name(program.bpf_prog()) },
            "s_kprobe_foo_1");
}

} // namespace bpfbytecode
} // namespace test
} // namespace bpftrace
