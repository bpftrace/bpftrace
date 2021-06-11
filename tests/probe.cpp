#include "ast/field_analyser.h"
#include "ast/resource_analyser.h"
#include "ast/semantic_analyser.h"
#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "fake_map.h"
#include "mocks.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace bpftrace {
namespace test {
namespace probe {

using bpftrace::ast::AttachPoint;
using bpftrace::ast::AttachPointList;
using bpftrace::ast::Probe;

void gen_bytecode(const std::string &input, std::stringstream &out)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);

  ASSERT_EQ(driver.parse_str(input), 0);

  ast::FieldAnalyser fields(driver.root_, *bpftrace);
  EXPECT_EQ(fields.analyse(), 0);

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
  compare_bytecode("hardware:cache-references:1000000 { 1 }", "h:cache-references:1000000 { 1 }");
  compare_bytecode("software:faults:1000 { 1 }", "s:faults:1000 { 1 }");
  compare_bytecode("interval:s:1 { 1 }", "i:s:1 { 1 }");
}

#ifdef HAVE_LIBBPF_BTF_DUMP
#ifdef HAVE_BCC_KFUNC

#include "btf_common.h"

class probe_btf : public test_btf
{
};

TEST_F(probe_btf, short_name)
{
  compare_bytecode("kfunc:func_1 { 1 }", "f:func_1 { 1 }");
  compare_bytecode("kretfunc:func_1 { 1 }", "fr:func_1 { 1 }");
  compare_bytecode("iter:task { 1 }", "it:task { 1 }");
  compare_bytecode("iter:task_file { 1 }", "it:task_file { 1 }");
}

#endif // HAVE_BCC_KFUNC
#endif // HAVE_LIBBPF_BTF_DUMP

} // namespace probe
} // namespace test
} // namespace bpftrace
