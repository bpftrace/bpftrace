
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/resource_analyser.h"
#include "ast/passes/semantic_analyser.h"

#include "bpftrace.h"
#include "clang_parser.h"
#include "driver.h"
#include "mocks.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace bpftrace::test::probe {

#include "btf_common.h"

using bpftrace::ast::AttachPoint;
using bpftrace::ast::AttachPointList;
using bpftrace::ast::Probe;

void gen_bytecode(const std::string &input, std::stringstream &out)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);

  ASSERT_EQ(driver.parse_str(input), 0);

  ast::FieldAnalyser fields(*bpftrace);
  fields.visit(driver.ctx.root);
  ASSERT_TRUE(driver.ctx.diagnostics().ok());

  ClangParser clang;
  clang.parse(driver.ctx.root, *bpftrace);

  ast::SemanticAnalyser semantics(driver.ctx, *bpftrace);
  semantics.analyse();
  ASSERT_TRUE(driver.ctx.diagnostics().ok());

  ast::ResourceAnalyser resource_analyser(*bpftrace);
  resource_analyser.visit(driver.ctx.root);
  bpftrace->resources = resource_analyser.resources();
  ASSERT_TRUE(driver.ctx.diagnostics().ok());

  ast::CodegenLLVM codegen(driver.ctx, *bpftrace);
  codegen.generate_ir();
  codegen.DumpIR(out);
}

void compare_bytecode(const std::string &input1, const std::string &input2)
{
  std::stringstream expected_output1;
  std::stringstream expected_output2;

  gen_bytecode(input1, expected_output1);
  gen_bytecode(input2, expected_output2);

  EXPECT_EQ(expected_output1.str(), expected_output2.str());
}

TEST(probe, short_name)
{
  compare_bytecode("tracepoint:a:b { args }", "t:a:b { args }");
  compare_bytecode("kprobe:f { pid }", "k:f { pid }");
  compare_bytecode("kretprobe:f { pid }", "kr:f { pid }");
  compare_bytecode("uprobe:sh:f { 1 }", "u:sh:f { 1 }");
  compare_bytecode("profile:hz:997 { 1 }", "p:hz:997 { 1 }");
  compare_bytecode("hardware:cache-references:1000000 { 1 }",
                   "h:cache-references:1000000 { 1 }");
  compare_bytecode("software:faults:1000 { 1 }", "s:faults:1000 { 1 }");
  compare_bytecode("interval:s:1 { 1 }", "i:s:1 { 1 }");
}

class probe_btf : public test_btf {};

TEST_F(probe_btf, short_name)
{
  compare_bytecode("fentry:func_1 { 1 }", "f:func_1 { 1 }");
  compare_bytecode("fexit:func_1 { 1 }", "fr:func_1 { 1 }");
  compare_bytecode("iter:task { 1 }", "it:task { 1 }");
  compare_bytecode("iter:task_file { 1 }", "it:task_file { 1 }");
  compare_bytecode("iter:task_vma { 1 }", "it:task_vma { 1 }");
}

} // namespace bpftrace::test::probe
