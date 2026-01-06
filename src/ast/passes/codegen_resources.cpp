#include "codegen_resources.h"

#include "types.h"

namespace bpftrace::ast {

CodegenResourceAnalyser::CodegenResourceAnalyser(
    const ::bpftrace::Config &config)
    : config_(config)
{
}

CodegenResources CodegenResourceAnalyser::analyse(Program &program)
{
  visit(program);
  return std::move(resources_);
}

void CodegenResourceAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "__builtin_elapsed") {
    resources_.needs_elapsed_map = true;
  }
}

} // namespace bpftrace::ast
