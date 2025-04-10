#pragma once

#include <fstream>
#include <iostream>
#include <regex>

#include "ast/attachpoint_parser.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/parser.h"
#include "ast/passes/pid_filter_pass.h"
#include "ast/passes/probe_analyser.h"
#include "ast/passes/recursion_check.h"
#include "ast/passes/resource_analyser.h"
#include "ast/passes/semantic_analyser.h"
#include "bpftrace.h"
#include "btf_common.h"
#include "clang_parser.h"
#include "driver.h"
#include "util/env.h"
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
  ast::ASTContext ast("stdin", input);

  // N.B. No tracepoint expansion.
  std::stringstream out;
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateFieldAnalyserPass())
                .add(CreateClangPass())
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateMapSugarPass())
                .add(ast::CreateSemanticPass())
                .add(ast::CreatePidFilterPass())
                .add(ast::CreateRecursionCheckPass())
                .add(ast::CreateSemanticPass())
                .add(ast::CreateResourcePass())
                .add(ast::CreateProbePass())
                .add(ast::CreateLLVMInitPass())
                .add(ast::CreateCompilePass())
                .add(ast::CreateDumpIRPass(out))
                .run();
  std::stringstream errs;
  ast.diagnostics().emit(errs);
  ASSERT_TRUE(ok && ast.diagnostics().ok()) << errs.str();

  uint64_t update_tests = 0;
  util::get_uint64_env_var("BPFTRACE_UPDATE_TESTS",
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
