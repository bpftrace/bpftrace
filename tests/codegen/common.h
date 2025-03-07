#pragma once

#include <fstream>
#include <iostream>

#include "ast/passes/codegen_llvm.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/pid_filter_pass.h"
#include "ast/passes/resource_analyser.h"
#include "ast/passes/semantic_analyser.h"
#include "bpftrace.h"
#include "btf_common.h"
#include "clang_parser.h"
#include "driver.h"
#include "gtest/gtest.h"

#include "../mocks.h"

namespace bpftrace::test::codegen {

#define NAME (::testing::UnitTest::GetInstance()->current_test_info()->name())

class codegen_btf : public test_btf {};

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

// This is the lower level codegen test entrypoint.
//
// The contract is that the `bpftrace` must be completely initialized and ready
// to go (eg. members replaced with mocks as necessary) before calling into
// here.
static void test(BPFtrace &bpftrace,
                 const std::string &input,
                 const std::string &name)
{
  Driver driver(bpftrace);
  ASSERT_EQ(driver.parse_str(input), 0);

  ast::FieldAnalyser fields(bpftrace);
  fields.visit(driver.ctx.root);
  ASSERT_TRUE(driver.ctx.diagnostics().ok());

  ClangParser clang;
  clang.parse(driver.ctx.root, bpftrace);

  ASSERT_EQ(driver.parse_str(input), 0);

  ast::PidFilterPass pid_filter(driver.ctx, bpftrace);
  pid_filter.visit(driver.ctx.root);

  ast::SemanticAnalyser semantics(driver.ctx, bpftrace);
  semantics.analyse();
  ASSERT_TRUE(driver.ctx.diagnostics().ok());

  ast::ResourceAnalyser resource_analyser(bpftrace);
  resource_analyser.visit(driver.ctx.root);
  bpftrace.resources = resource_analyser.resources();
  ASSERT_TRUE(driver.ctx.diagnostics().ok());

  std::stringstream out;
  ast::CodegenLLVM codegen(driver.ctx, bpftrace);
  codegen.generate_ir();
  codegen.DumpIR(out);
  // Test that generated code compiles cleanly
  codegen.optimize();
  codegen.emit(false);

  uint64_t update_tests = 0;
  get_uint64_env_var("BPFTRACE_UPDATE_TESTS",
                     [&](uint64_t x) { update_tests = x; });
  if (update_tests >= 1) {
    std::cerr << "Running in update mode, test is skipped" << std::endl;
    std::ofstream file(TEST_CODEGEN_LOCATION + name + ".ll");
    file << out.str();
    return;
  }

  std::string expected_output = get_expected(name);

  EXPECT_EQ(expected_output, out.str())
      << "the following program failed: '" << input << "'";
}

// This is the common case codegen test entrypoint.
//
// Please prefer to use this interface.
static void test(const std::string &input,
                 const std::string &name,
                 bool safe_mode = true)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->safe_mode_ = safe_mode;

  test(*bpftrace, input, name);
}

} // namespace bpftrace::test::codegen
