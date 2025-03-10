#pragma once

#include <fstream>
#include <iostream>
#include <regex>

#include "ast/attachpoint_parser.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/pid_filter_pass.h"
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
  Driver driver(ast, bpftrace);

  driver.parse();
  ASSERT_TRUE(ast.diagnostics().ok());

  ast::AttachPointParser ap_parser(ast, bpftrace, false);
  ap_parser.parse();
  ASSERT_TRUE(ast.diagnostics().ok());

  ast::FieldAnalyser fields(bpftrace);
  fields.visit(ast.root);
  ASSERT_TRUE(ast.diagnostics().ok());

  ClangParser clang;
  clang.parse(ast.root, bpftrace);

  driver.parse();
  ASSERT_TRUE(ast.diagnostics().ok());

  ap_parser.parse();
  ASSERT_TRUE(ast.diagnostics().ok());

  ast::PidFilterPass pid_filter(ast, bpftrace);
  pid_filter.visit(ast.root);
  ASSERT_TRUE(ast.diagnostics().ok());

  ast::SemanticAnalyser semantics(ast, bpftrace);
  semantics.analyse();
  ASSERT_TRUE(ast.diagnostics().ok());

  ast::ResourceAnalyser resource_analyser(bpftrace);
  resource_analyser.visit(ast.root);
  bpftrace.resources = resource_analyser.resources();
  ASSERT_TRUE(ast.diagnostics().ok());

  std::stringstream out;
  ast::CodegenLLVM codegen(ast, bpftrace);
  codegen.generate_ir();
  codegen.DumpIR(out);
  // Test that generated code compiles cleanly
  codegen.optimize();
  codegen.emit(false);

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
