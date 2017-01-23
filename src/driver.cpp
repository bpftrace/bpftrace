#include <iostream>

#include "codegen_llvm.h"
#include "driver.h"
#include "printer.h"
#include "semantic_analyser.h"

namespace ebpf {
namespace bpftrace {

int Driver::parse()
{
  return parser_.parse();
}

int Driver::parse(const std::string &f)
{
  if (!(yyin = fopen(f.c_str(), "r"))) {
    std::cerr << "Could not open file" << std::endl;
    return -1;
  }
  return parser_.parse();
}

void Driver::dump_ast(std::ostream &out)
{
  ast::Printer p = ebpf::bpftrace::ast::Printer(out);
  root_->accept(p);
}

int Driver::analyse()
{
  ast::SemanticAnalyser semantics(root_, bpftrace_);
  return semantics.analyse();
}

int Driver::compile()
{
  ast::CodegenLLVM llvm(root_, bpftrace_);
  return llvm.compile();
}

} // namespace bpftrace
} // namespace ebpf
