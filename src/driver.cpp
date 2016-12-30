#include <istream>
#include <ostream>

#include "driver.h"
#include "printer.h"
#include "codegen.h"

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

int Driver::dump_ast(std::ostream &out)
{
  ast::Printer p = ebpf::bpftrace::ast::Printer(out);
  root_->accept(p);
}

} // namespace bpftrace
} // namespace ebpf
