#pragma once

#include "parser.tab.hh"
#include "ast.h"

#include <llvm/ExecutionEngine/MCJIT.h>
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
             module_(make_unique<Module>("bpftrace", context_))
             { }

  int parse();
  int parse(const std::string &f);
  void dump_ast(std::ostream &out);
  int compile();

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
  std::unique_ptr<Module> module_;
  std::unique_ptr<ExecutionEngine> ee_;
};

} // namespace bpftrace
} // namespace ebpf
