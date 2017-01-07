#include <iostream>

#include "driver.h"
#include "printer.h"
#include "codegen_llvm.h"
#include "codegen_bcc.h"

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

int Driver::compile()
{
  ast::CodegenLLVM llvm(root_);
  int result_llvm = llvm.compile();

  ast::CodegenBCC bcc(root_);
  int result_bcc = bcc.compile();
  std::cout << bcc.code.str();
  return result_llvm && result_bcc;
}

} // namespace bpftrace
} // namespace ebpf
