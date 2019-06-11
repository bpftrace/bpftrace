#pragma once

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "fake_map.h"
#include "semantic_analyser.h"
#include "tracepoint_format_parser.h"

namespace bpftrace {
namespace test {
namespace codegen {

class MockBPFtrace : public BPFtrace {
public:
  MOCK_METHOD1(add_probe, int(ast::Probe &p));
  MOCK_METHOD3(find_wildcard_matches, std::set<std::string>(
        const std::string &prefix,
        const std::string &func,
        const std::string &file_name));
};

class MockTracepointFormatParser : public TracepointFormatParser
{
public:
  static std::string get_tracepoint_struct_public(std::istream &format_file, const std::string &category, const std::string &event_name)
  {
    return get_tracepoint_struct(format_file, category, event_name);
  }
};

const std::string header = R"HEAD(; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

)HEAD";

static void test(
    BPFtrace &bpftrace,
    const std::string &input,
    const std::string &expected_output)
{
  Driver driver(bpftrace);
  FakeMap::next_mapfd_ = 1;

  ASSERT_EQ(driver.parse_str(input), 0);

  ClangParser clang;
  clang.parse(driver.root_, bpftrace);

  ASSERT_EQ(driver.parse_str(input), 0);

  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);
  ASSERT_EQ(semantics.create_maps(true), 0);

  std::stringstream out;
  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  codegen.compile(DebugLevel::kDebug, out);

  std::string full_expected_output = header + expected_output;
  EXPECT_EQ(full_expected_output, out.str());
  if(::testing::Test::HasFailure()) {
    std::cerr << "Program: '" << input <<"'" <<  std::endl;
  }
}

static void test(
    const std::string &input,
    const std::string &expected_output,
    bool safe_mode = true)
{
  BPFtrace bpftrace;
  bpftrace.safe_mode_ = safe_mode;
  test(bpftrace, input, expected_output);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
