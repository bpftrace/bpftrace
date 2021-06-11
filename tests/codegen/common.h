#pragma once

#include <regex>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "../mocks.h"
#include "ast/resource_analyser.h"
#include "ast/semantic_analyser.h"
#include "bpffeature.h"
#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "fake_map.h"
#include "tracepoint_format_parser.h"

namespace bpftrace {
namespace test {
namespace codegen {

#define NAME (::testing::UnitTest::GetInstance()->current_test_info()->name())

static std::string get_expected(const std::string &name)
{
  std::string fname = TEST_CODEGEN_LOCATION + name + ".ll";
  std::ifstream file;

  file.open(fname);
  if (file.good())
    return std::string((std::istreambuf_iterator<char>(file)),
                       (std::istreambuf_iterator<char>()));

  throw std::runtime_error("Could not find codegen result for test: " + name);
}

static void test(BPFtrace &bpftrace,
                 const std::string &input,
                 const std::string &name)
{
  Driver driver(bpftrace);
  ASSERT_EQ(driver.parse_str(input), 0);

  ClangParser clang;
  clang.parse(driver.root_, bpftrace);

  ASSERT_EQ(driver.parse_str(input), 0);

  // Override to mockbpffeature.
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);

  ast::ResourceAnalyser resource_analyser(driver.root_);
  auto resources = resource_analyser.analyse();
  ASSERT_EQ(resources.create_maps(bpftrace, true), 0);
  bpftrace.resources = resources;

  std::stringstream out;
  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  codegen.generate_ir();
  codegen.DumpIR(out);
  // Test that generated code compiles cleanly
  codegen.optimize();
  codegen.emit();

  uint64_t update_tests = 0;
  if (get_uint64_env_var("BPFTRACE_UPDATE_TESTS", update_tests) &&
      update_tests >= 1)
  {
    std::cerr << "Running in update mode, test is skipped" << std::endl;
    std::ofstream file(TEST_CODEGEN_LOCATION + name + ".ll");
    file << out.str();
    return;
  }

  std::string expected_output = get_expected(name);

  EXPECT_EQ(expected_output, out.str())
      << "the following program failed: '" << input << "'";
}

static void test(const std::string &input,
                 const std::string &name,
                 bool safe_mode = true)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->safe_mode_ = safe_mode;
  test(*bpftrace, input, name);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
