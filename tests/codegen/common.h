#pragma once

#include <regex>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

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

namespace bpftrace {
namespace test {
namespace codegen {

#define NAME (::testing::UnitTest::GetInstance()->current_test_info()->name())

static std::string rewrite_memset_call(const std::string &line)
{
#if LLVM_VERSION_MAJOR < 7
  // clang-format off
  //FROM: call void @llvm.memset.p0i8.i64(i8* nonnull align 8 %2, i8 0, i64 16,        i1 false)
  //TO:   call void @llvm.memset.p0i8.i64(i8* nonnull         %2, i8 0, i64 16, i32 8, i1 false)
  // clang-format on

  auto parts = split_string(line, ' ');
  std::stringstream buf;

  std::string alignment;
  for (auto it = parts.begin(); it != parts.end(); it++)
  {
    if (*it == "align")
    {
      alignment = *(it + 1);
      parts.erase(it, it + 2);
      break;
    }
  }

  parts.insert(parts.end() - 2, std::string("i32 ") + alignment + ",");

  buf << parts.at(0);
  for (unsigned int i = 1; i < parts.size(); i++)
  {
    buf << " " << parts.at(i);
  }

  return buf.str();
#elif LLVM_VERSION_MAJOR >= 10
  // clang-format off
  // FROM: call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %1, i64 0, i64 16, i1 false)
  // TO:   call void @llvm.memset.p0i8.i64(i8* nonnull align 1 dereferenceable(16) %1, i64 0, i64 16, i1 false)
  // clang-format on
  static std::regex re("\\((i8\\* nonnull align \\d+) %([^,]+), "
                       "([^,]+), i64 (\\d+), ([^\\)]+)\\)");
  return std::regex_replace(line,
                            re,
                            "($1 dereferenceable($4) %$2, $3, i64 $4, $5)");
#else
  return line;
#endif
}

#if LLVM_VERSION_MAJOR >= 10
static std::string rewrite_memset_decl(const std::string &line
                                       __attribute__((unused)))
{
  return std::string("declare void @llvm.memset.p0i8.i64(i8* nocapture "
                     "writeonly %0, i8 %1, i64 %2, i1 immarg %3) #1");
#elif LLVM_VERSION_MAJOR == 9
static std::string rewrite_memset_decl(const std::string &line
                                       __attribute__((unused)))
{
  return std::string("declare void @llvm.memset.p0i8.i64(i8* nocapture "
                     "writeonly, i8, i64, i1 immarg) #1");
#elif LLVM_VERSION_MAJOR < 7
static std::string rewrite_memset_decl(const std::string &line
                                       __attribute__((unused)))
{
  return std::string("declare void @llvm.memset.p0i8.i64(i8* nocapture "
                     "writeonly, i8, i64, i32, i1) #1");
#else
static std::string rewrite_memset_decl(const std::string &line)
{
  return std::string(line);
#endif
}

static std::string rewrite_memcpy_call(const std::string &line)
{
#if LLVM_VERSION_MAJOR < 7
  // clang-format off
  //FROM: call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %4, i8* nonnull align 1 i32 1, %lookup_elem, i64 32, i1 false)
  //TO:  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %4, i8* nonnull %lookup_elem, i64 32, i32 1, i1 false)
  // clang-format on
  auto parts = split_string(line, ' ');
  std::stringstream buf;
  std::string alignment;
  for (auto it = parts.begin(); it != parts.end(); it++)
  {
    if (*it == "align")
    {
      // We have some code creates a 2nd address space, in that case only the
      // value after the first align is valid. See logical_and_or_different_type
      if (alignment.empty())
        alignment = *(it + 1);
      parts.erase(it, it + 2);
    }
  }

  parts.insert(parts.end() - 2, std::string("i32 ") + alignment + ",");

  buf << parts.at(0);
  for (unsigned int i = 1; i < parts.size(); i++)
  {
    buf << " " << parts.at(i);
  }
  return buf.str();
#elif LLVM_VERSION_MAJOR >= 10
  // clang-format off
  // FROM: call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull align 1 %1, i8* nonnull align 1 %2, i64 16, i1 false)
  // TO:   call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull align 1 dereferenceable(16) %1, i8* nonnull align 1 dereferenceable(16) %2, i64 16, i1 false)
  // clang-format on
  if (line.find("addrspace") != std::string::npos)
  {
    static std::regex re(
        "\\((i8\\* nonnull align [^,]+) %(\\d+), (i8 "
        "addrspace\\(\\d+\\)\\* align \\d+) (null), i64 (\\d+), "
        "([^\\)]+)\\)");
    return std::regex_replace(
        line,
        re,
        "($1 dereferenceable($5) %$2, $3 dereferenceable($5) $4, i64 $5, $6)");
  }
  static std::regex re(
      "\\((i8\\* nonnull align \\d+) %([^,]+), (i8\\* nonnull align "
      "\\d+) %([^,]+), i64 (\\d+), (i1 false)\\)");
  return std::regex_replace(
      line,
      re,
      "($1 dereferenceable($5) %$2, $3 dereferenceable($5) %$4, i64 $5, $6)");
#else
  return line;
#endif
}

static std::string rewrite_memcpy_decl(const std::string &line)
{
#if LLVM_VERSION_MAJOR >= 10
  if (line.find("addrspace") != std::string::npos)
    return std::string("declare void @llvm.memcpy.p0i8.p64i8.i64(i8* noalias "
                       "nocapture writeonly %0, i8 "
                       "addrspace(64)* noalias nocapture readonly %1, i64 %2, "
                       "i1 immarg %3) #1");
  return std::string(
      "declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture "
      "writeonly %0, i8* noalias nocapture readonly %1, i64 %2, i1 immarg %3) "
      "#1");
#elif LLVM_VERSION_MAJOR == 9
  if (line.find("addrspace") != std::string::npos)
    return std::string(
        "declare void @llvm.memcpy.p0i8.p64i8.i64(i8* nocapture writeonly, i8 "
        "addrspace(64)* nocapture readonly, i64, i1 immarg) #1");
  return std::string("declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture "
                     "writeonly, i8* nocapture readonly, i64, i1 immarg) #1");
#elif LLVM_VERSION_MAJOR < 7
  if (line.find("addrspace") != std::string::npos)
    return std::string(
        "declare void @llvm.memcpy.p0i8.p64i8.i64(i8* nocapture writeonly, i8 "
        "addrspace(64)* nocapture readonly, i64, i32, i1) #1");
  return std::string("declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture "
                     "writeonly, i8* nocapture readonly, i64, i32, i1) #1");
#else
  return line;
#endif
}

static std::string rewrite_lifetime_end_decl(const std::string &line)
{
  (void)line;
#if LLVM_VERSION_MAJOR >= 10
  return std::string("declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* "
                     "nocapture %1) #1");
#elif LLVM_VERSION_MAJOR == 9
  return std::string(
      "declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #1");
#else
  return std::string(
      "declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1");
#endif
}

static std::string rewrite_lifetime_start_decl(const std::string &line)
{
  (void)line;
#if LLVM_VERSION_MAJOR >= 10
  return std::string("declare void @llvm.lifetime.start.p0i8(i64 immarg %0, "
                     "i8* nocapture %1) #1");
#elif LLVM_VERSION_MAJOR == 9
  return std::string(
      "declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #1");
#else
  return std::string(
      "declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1");
#endif
}

static std::string rewrite_bpf_pseudo(const std::string &line)
{
#if LLVM_VERSION_MAJOR >= 10
  // FROM: declare i64 @llvm.bpf.pseudo(i64, i64) #0
  // TO:   declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0
  (void)line;
  return std::string("declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0");
#else
  return line;
#endif
}

static std::string rewrite_function_attrs(const std::string &line)
{
#if LLVM_VERSION_MAJOR >= 10
  // FROM: ;Function Attrs: argmemonly nounwind
  // TO:   ;Function Attrs: argmemonly nounwind willreturn
  (void)line;
  return std::string("; Function Attrs: argmemonly nounwind willreturn");
#else
  return line;
#endif
}

static std::string rewrite_attrs(const std::string &line)
{
#if LLVM_VERSION_MAJOR >= 10
  // FROM: attributes #1 = { argmemonly nounwind }
  // TO:   attributes #1 = { argmemonly nounwind willreturn }
  (void)line;
  return std::string("attributes #1 = { argmemonly nounwind willreturn }");
#else
  return line;
#endif
}

static std::string rewrite_local_unnamed_addr(const std::string &line)
{
#if LLVM_VERSION_MAJOR >= 10
  // FROM: define i64 @BEGIN(i8*) local_unnamed_addr section \"s_BEGIN_1\" {
  // TO:   define i64 @BEGIN(i8* %0) local_unnamed_addr section \"s_BEGIN_1\" {
  static std::regex re("(@[^\\(]+)\\(([^\\)]+)\\)");
  return std::regex_replace(line, re, "$1($2 %0)");
#else
  return line;
#endif
}

static std::string rewrite_gep(const std::string &line)
{
#if LLVM_VERSION_MAJOR >= 10
  // FROM: %28 = getelementptr inbounds [4 x i8], [4 x i8]* %27, i64 0, i64 0
  // TO:   %28 = getelementptr [4 x i8], [4 x i8]* %27, i64 0, i64 0
  static std::regex re(
      "(getelementptr) inbounds (\\[\\d+ x i\\d+\\], \\[\\d+ x "
      "i\\d+\\]\\* %\\d+, i\\d+ 0, i\\d+ 0)");
  return std::regex_replace(line, re, "$1 $2");
#else
  return line;
#endif
}

static std::string rewrite(const std::string &ir)
{
  std::stringstream buf;
  for (const auto &line : split_string(ir, '\n'))
  {
    if (line.find("call void @llvm.memset") != std::string::npos)
      buf << rewrite_memset_call(line);
    else if (line.find("declare void @llvm.memset") != std::string::npos)
      buf << rewrite_memset_decl(line);
    else if (line.find("call void @llvm.memcpy") != std::string::npos)
      buf << rewrite_memcpy_call(line);
    else if (line.find("declare void @llvm.memcpy") != std::string::npos)
      buf << rewrite_memcpy_decl(line);
    else if (line.find("declare void @llvm.lifetime.start") !=
             std::string::npos)
      buf << rewrite_lifetime_start_decl(line);
    else if (line.find("declare void @llvm.lifetime.end") != std::string::npos)
      buf << rewrite_lifetime_end_decl(line);
    else if (line.find("declare i64 @llvm.bpf.pseudo") != std::string::npos)
      buf << rewrite_bpf_pseudo(line);
    else if (line.find("; Function Attrs: argmemonly nounwind") !=
             std::string::npos)
      buf << rewrite_function_attrs(line);
    else if (line.find("attributes #1 = { argmemonly nounwind }") !=
             std::string::npos)
      buf << rewrite_attrs(line);
    else if (line.find("local_unnamed_addr") != std::string::npos)
      buf << rewrite_local_unnamed_addr(line);
    else if (line.find("getelementptr inbounds") != std::string::npos)
      buf << rewrite_gep(line);
    else
      buf << line;
    buf << std::endl;
  }
  return buf.str();
}

static std::string get_expected(const std::string &name)
{
  // Search version specific (_LLVM-X) first, if non exists rewrite the default
  std::stringstream versioned;
  versioned << TEST_CODEGEN_LOCATION << name << "_LLVM-" << LLVM_VERSION_MAJOR
            << ".ll";
  std::string fname = TEST_CODEGEN_LOCATION + name + ".ll";
  std::ifstream file;

  file.open(versioned.str());
  if (file.good())
    return std::string((std::istreambuf_iterator<char>(file)),
                       (std::istreambuf_iterator<char>()));

  file.open(fname);
  if (file.good())
    return rewrite(std::string((std::istreambuf_iterator<char>(file)),
                               (std::istreambuf_iterator<char>())));

  throw std::runtime_error("Could not find codegen result for test: " + name);
}

static void test(BPFtrace &bpftrace,
                 const std::string &input,
                 const std::string &name)
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
  codegen.generate_ir();
  codegen.optimize();
  codegen.DumpIR(out);
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
  BPFtrace bpftrace;
  bpftrace.safe_mode_ = safe_mode;
  test(bpftrace, input, name);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
