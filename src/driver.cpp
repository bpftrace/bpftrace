#include <istream>
#include <ostream>

#include "driver.h"
#include "printer.h"
#include "codegen_llvm.h"

#include <llvm/Support/TargetRegistry.h>

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
  ast::CodegenLLVM c(*module_, context_);
  root_->accept(c);
  module_->dump();

  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFAsmPrinter();

  std::string targetTriple = "bpf-pc-linux";
  module_->setTargetTriple(targetTriple);

  std::string error;
  const Target *target = TargetRegistry::lookupTarget(targetTriple, error);
  if (!target) {
    std::cerr << "Could not create LLVM target" << std::endl;
    abort();
  }

  TargetOptions opt;
  auto RM = Optional<Reloc::Model>();
  TargetMachine *targetMachine = target->createTargetMachine(targetTriple, "generic", "", opt, RM);
  module_->setDataLayout(targetMachine->createDataLayout());

  // TODO: Run some optimisation passes here

  EngineBuilder builder(move(module_));
  ee_ = std::unique_ptr<ExecutionEngine>(builder.create());
  ee_->finalizeObject();
}

} // namespace bpftrace
} // namespace ebpf
