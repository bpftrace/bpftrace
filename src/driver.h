#pragma once

#include "parser.tab.hh"
#include "ast.h"

#include <llvm/IR/Module.h>

#define YY_DECL ebpf::bpftrace::Parser::symbol_type yylex(ebpf::bpftrace::Driver &driver)
YY_DECL;

extern FILE *yyin;

namespace ebpf {
namespace bpftrace {

using namespace llvm;

class Driver {
public:
  Driver() : parser_(*this),
             module_("bpftrace", context_)
             { }

  int parse();
  int parse(const std::string &f);
  int dump_ast(std::ostream &out);

  void error(const location &l, const std::string &m)
  {
    std::cerr << l << ": " << m << std::endl;
  }

  void error(const std::string &m)
  {
    std::cerr << m << std::endl;
  }

  ast::Program *root_;

private:
  Parser parser_;
  LLVMContext context_;
  Module module_;
};

} // namespace bpftrace
} // namespace ebpf
