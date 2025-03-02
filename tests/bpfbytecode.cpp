#include "bpfbytecode.h"
#include "ast/attachpoint_parser.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/semantic_analyser.h"
#include "driver.h"
#include "mocks.h"

#include "gtest/gtest.h"

namespace bpftrace::test::bpfbytecode {

BpfBytecode codegen(const std::string &input)
{
  auto bpftrace = get_mock_bpftrace();

  ast::ASTContext ast("stdin", input);
  Driver driver(ast, *bpftrace);

  driver.parse();
  bool parse_ok = ast.diagnostics().ok();
  EXPECT_TRUE(parse_ok);
  if (!parse_ok) {
    return {};
  }

  ast::AttachPointParser ap_parser(ast, *bpftrace, false);
  ap_parser.parse();

  ast::SemanticAnalyser semantics(ast, *bpftrace);
  semantics.analyse();
  EXPECT_TRUE(ast.diagnostics().ok());

  ast::CodegenLLVM codegen(ast, *bpftrace);
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

} // namespace bpftrace::test::bpfbytecode
