#include "ast/passes/ap_probe_expansion.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/clang_build.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/control_flow_analyser.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/resolve_imports.h"
#include "ast/passes/resource_analyser.h"
#include "ast/passes/types/type_system.h"
#include "bpftrace.h"
#include "btf.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::probe {

using bpftrace::ast::AttachPoint;
using bpftrace::ast::AttachPointList;
using bpftrace::ast::Probe;

void gen_bytecode(const std::string &input, std::stringstream &out)
{
  auto bpftrace = get_mock_bpftrace();
  ast::ASTContext ast("stdin", input);

  ast::CDefinitions no_c_defs; // Output from clang parser.
  // Because some stdlib's bpf.c file is conflicting with the custom BTF we
  // generate for the test, just disable stdlib for this test right now.
  ast::Imports no_imports;

  // N.B. No macro expansion.
  auto ok = ast::PassManager()
                .put(ast)
                .put<BPFtrace>(*bpftrace)
                .put(get_mock_function_info())
                .put(no_c_defs)
                .put(no_imports)
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateControlFlowPass())
                .add(ast::CreateProbeAndApExpansionPass())
                .add(ast::CreateMacroExpansionPass())
                .add(CreateParseBTFPass())
                .add(ast::CreateMapSugarPass())
                .add(ast::CreateFieldAnalyserPass())
                .add(ast::CreateNamedParamsPass())
                .add(ast::CreateLLVMInitPass())
                .add(ast::CreateClangBuildPass())
                .add(ast::CreateTypeSystemPass())
                .add(ast::CreateResourcePass())
                .add(ast::AllCompilePasses())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());
  auto &obj = ok->get<ast::BpfObject>();
  out.write(obj.data.data(), obj.data.size());
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
  compare_bytecode("tracepoint:sched:sched_one { args }",
                   "t:sched:sched_one { args }");
  compare_bytecode("kprobe:f { pid }", "k:f { pid }");
  compare_bytecode("kretprobe:f { pid }", "kr:f { pid }");
  compare_bytecode("uprobe:/bin/sh:f { 1 }", "u:/bin/sh:f { 1 }");
  compare_bytecode("profile:hz:997 { 1 }", "p:hz:997 { 1 }");
  compare_bytecode("hardware:cache-references:1000000 { 1 }",
                   "h:cache-references:1000000 { 1 }");
  compare_bytecode("software:faults:1000 { 1 }", "s:faults:1000 { 1 }");
  compare_bytecode("interval:s:1 { 1 }", "i:s:1 { 1 }");
}

TEST(probe, case_insensitive)
{
  compare_bytecode("tracepoint:sched:sched_one { args }",
                   "traCepoInt:sched:sched_one { args }");
  compare_bytecode("kprobe:f { pid }", "KPROBE:f { pid }");
  compare_bytecode("BEGIN { pid }", "begin { pid }");
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
