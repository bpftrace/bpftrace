#include <iostream>
#include "bpftrace.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "printer.h"
#include "semantic_analyser.h"

using namespace ebpf::bpftrace;

int main(int argc, char *argv[])
{
  int result;
  Driver driver;
  if (argc == 1)
    result = driver.parse();
  else
    result = driver.parse(argv[1]);

  if (result)
    return result;

  BPFtrace bpftrace;

  ast::Printer p = ebpf::bpftrace::ast::Printer(std::cout);
  driver.root_->accept(p);

  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  result = semantics.analyse();
  if (result)
    return result;

  ast::CodegenLLVM llvm(driver.root_, bpftrace);
  result = llvm.compile();
  if (result)
    return result;

  bpftrace.attach_probes();

  return 0;
}
