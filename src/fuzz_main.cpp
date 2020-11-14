// main function for fuzzing
// To build this, add -DBUILD_FUZZ=1 CMake option
// The compiled binary name is "bpftrace_fuzz"

#include <array>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <limits>
#include <optional>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "ast/callback_visitor.h"
#include "bpffeature.h"
#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "field_analyser.h"
#include "log.h"
#include "output.h"
#include "semantic_analyser.h"
#include "tracepoint_format_parser.h"

#define DEFAULT_NODE_MAX 200

using namespace bpftrace;

int main(int argc, char* argv[])
{
  if (getuid() != 0)
    return 1;

  std::unique_ptr<Output> output;
  std::ostream* os = &std::cout;
  output = std::make_unique<TextOutput>(*os);

  BPFtrace bpftrace(std::move(output));
  DISABLE_LOG(WARNING);
  bpftrace.safe_mode_ = 0;

  Driver driver(bpftrace);
  // Read inputs
  std::stringstream buf;
  std::string line;
  if (argc <= 1)
  {
    // Input from stdin (AFL's default)
    while (std::getline(std::cin, line))
      buf << line << std::endl;
    driver.source("stdin", buf.str());
  }
  else
  {
    // Read from file
    std::string filename(argv[1]);
    std::ifstream file(filename);
    if (file.fail())
      return 1;
    buf << file.rdbuf();
    driver.source(filename, buf.str());
  }

  // Create AST
  auto err = driver.parse();
  if (err)
    return err;

  // Limit node size
  uint64_t node_max = DEFAULT_NODE_MAX;
  if (!get_uint64_env_var("BPFTRACE_NODE_MAX", node_max))
    return 1;
  uint64_t node_count = 0;
  ast::CallbackVisitor counter(
      [&](ast::Node* node __attribute__((unused))) { node_count += 1; });
  driver.root_->accept(counter);
  if (node_count > node_max)
    return 1;

  // Field Analyzer
  ast::FieldAnalyser fields(driver.root_, bpftrace);
  err = fields.analyse();
  if (err)
    return err;

  // Tracepoint parser
  if (TracepointFormatParser::parse(driver.root_, bpftrace) == false)
    return 1;

  // ClangParser
  ClangParser clang;
  std::vector<std::string> extra_flags;
  {
    struct utsname utsname;
    uname(&utsname);
    std::string ksrc, kobj;
    auto kdirs = get_kernel_dirs(utsname);
    ksrc = std::get<0>(kdirs);
    kobj = std::get<1>(kdirs);

    if (ksrc != "")
      extra_flags = get_kernel_cflags(utsname.machine, ksrc, kobj);
  }
  extra_flags.push_back("-include");
  extra_flags.push_back(CLANG_WORKAROUNDS_H);
  if (!clang.parse(driver.root_, bpftrace, extra_flags))
    return 1;
  err = driver.parse();
  if (err)
    return err;

  // Semantic Analyzer
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, false);
  err = semantics.analyse();
  if (err)
    return err;

#if defined(TEST_SEMANTIC)
  return 0;
#endif

  // Create maps
  err = semantics.create_maps(true);
  if (err)
    return err;

  // Codegen
  ast::CodegenLLVM llvm(driver.root_, bpftrace);
  std::unique_ptr<BpfOrc> bpforc;
  try
  {
    llvm.generate_ir();
    llvm.optimize();
    bpforc = llvm.emit();
  }
  catch (const std::system_error& ex)
  {
    return 1;
  }
  catch (const std::exception& ex)
  {
    // failed to compile
    return 1;
  }

  // for debug
  // LOG(INFO) << "ok";

  return 0;
}
