#pragma once

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "../mocks.h"
#include "bpffeature.h"
#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "fake_map.h"
#include "semantic_analyser.h"
#include "tracepoint_format_parser.h"

#include <cstdio>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fcntl.h>

namespace bpftrace {
namespace test {
namespace codegen {

const std::string header = R"HEAD(; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf-pc-linux"

)HEAD";


static int llvm_validate_ir(const std::string &data)
{
  // TODO: Remove hardcode
  char cmd[] = "/usr/bin/llvm-as-7 -o /dev/null";
  FILE *pipe = popen(cmd, "w");
  if (!pipe) {
    return 1;
  }

  fputs(data.c_str(), pipe);
  return pclose(pipe);
}

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

  MockBPFfeature feature;
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, feature);
  ASSERT_EQ(semantics.analyse(), 0);
  ASSERT_EQ(semantics.create_maps(true), 0);

  std::stringstream out;
  ast::CodegenLLVM codegen(driver.root_, bpftrace);
  codegen.compile(DebugLevel::kDebug, out);

  std::string full_expected_output = header + expected_output;
  /* EXPECT_EQ(full_expected_output, out.str()) << "the following program failed: '" << input << "'"; */

  EXPECT_EQ(llvm_validate_ir(out.str()), 0) << "Validation of LLVM IR failed for:" << std::endl
                                            << input << std::endl
                                            << "invalid IR: " << std::endl << out.str();

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
