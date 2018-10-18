#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "fake_map.h"
#include "semantic_analyser.h"

namespace bpftrace
{
namespace test
{
namespace probe
{

using bpftrace::ast::AttachPoint;
using bpftrace::ast::AttachPointList;
using bpftrace::ast::Probe;

void gen_bytecode(const std::string &input, std::stringstream &out)
{
	BPFtrace bpftrace;
	Driver driver;
	FakeMap::next_mapfd_ = 1;

	ASSERT_EQ(driver.parse_str(input), 0);

	ClangParser clang;
	clang.parse(driver.root_, bpftrace.structs_);

	ast::SemanticAnalyser semantics(driver.root_, bpftrace);
	ASSERT_EQ(semantics.analyse(), 0);
	ASSERT_EQ(semantics.create_maps(true), 0);

	ast::CodegenLLVM codegen(driver.root_, bpftrace);
	codegen.compile(DebugLevel::kDebug, out);
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
	compare_bytecode("uprobe:path:f { 1 }", "u:path:f { 1 }");
	compare_bytecode("profile:hz:997 { 1 }", "p:hz:997 { 1 }");
	compare_bytecode("hardware:cache-references:1000000 { 1 }", "h:cache-references:1000000 { 1 }");
	compare_bytecode("software:faults:1000 { 1 }", "s:faults:1000 { 1 }");
	compare_bytecode("interval:s:1 { 1 }", "i:s:1 { 1 }");
}

} // namespace probe
} // namespace test
} // namespace bpftrace
