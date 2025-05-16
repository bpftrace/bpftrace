#include "bpfbytecode.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/parser.h"
#include "ast/passes/semantic_analyser.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::bpfbytecode {

BpfBytecode codegen(const std::string &input)
{
  auto bpftrace = get_mock_bpftrace();

  ast::ASTContext ast("stdin", input);

  auto ok = ast::PassManager()
                .put(ast)
                .put<BPFtrace>(*bpftrace)
                .add(ast::AllParsePasses())
                .add(ast::CreateSemanticPass())
                .add(ast::AllCompilePasses())
                .run();
  EXPECT_TRUE(ok && ast.diagnostics().ok());
  auto &output = ok->get<BpfBytecode>();
  return std::move(output);
}

TEST(bpfbytecode, create_programs)
{
  auto bytecode = codegen("kprobe:foo { 1 }");

  Probe foo;
  foo.type = ProbeType::kprobe;
  foo.name = "kprobe:mock_vmlinux:foo";
  foo.index = 1;

  auto &program = bytecode.getProgramForProbe(foo);

  EXPECT_EQ(std::string_view{ bpf_program__name(program.bpf_prog()) },
            "kprobe_mock_vmlinux_foo_1");
  EXPECT_EQ(std::string_view{ bpf_program__section_name(program.bpf_prog()) },
            "s_kprobe_mock_vmlinux_foo_1");
}

} // namespace bpftrace::test::bpfbytecode
