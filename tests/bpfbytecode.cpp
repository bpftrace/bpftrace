#include "bpfbytecode.h"
#include "ast/passes/clang_build.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/parser.h"
#include "ast/passes/semantic_analyser.h"
#include "ast/passes/type_system.h"
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
                .put(get_mock_function_info())
                .add(ast::AllParsePasses())
                .add(ast::CreateLLVMInitPass())
                .add(ast::CreateClangBuildPass())
                .add(ast::CreateTypeSystemPass())
                .add(ast::CreateSemanticPass())
                .add(ast::AllCompilePasses())
                .run();
  if (!ok) {
    EXPECT_TRUE(bool(ok)) << ok.takeError();
  }
  std::stringstream out;
  ast.diagnostics().emit(out);
  EXPECT_TRUE(ast.diagnostics().ok()) << out.str();
  auto &output = ok->get<BpfBytecode>();
  return std::move(output);
}

TEST(bpfbytecode, create_programs)
{
  auto bytecode = codegen("kprobe:f { 1 }");

  Probe f;
  f.type = ProbeType::kprobe;
  f.name = "kprobe:f";
  f.index = 1;

  auto &program = bytecode.getProgramForProbe(f);

  EXPECT_EQ(std::string_view{ bpf_program__name(program.bpf_prog()) },
            "kprobe_f_1");
  EXPECT_EQ(std::string_view{ bpf_program__section_name(program.bpf_prog()) },
            "s_kprobe_f_1");
}

} // namespace bpftrace::test::bpfbytecode
