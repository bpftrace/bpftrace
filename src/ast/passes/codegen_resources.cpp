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
  } else if (builtin.ident == "__builtin_kstack" ||
             builtin.ident == "__builtin_ustack") {
    resources_.stackid_maps.insert(StackType{ .mode = config_.stack_mode });
  }
}

void CodegenResourceAnalyser::visit(Call &call)
{
  Visitor::visit(call);

  if (call.func == "join") {
    resources_.needs_join_map = true;
  } else if (call.func == "__builtin_kstack" ||
             call.func == "__builtin_ustack") {
    resources_.stackid_maps.insert(call.return_type.stack_type);
  }
}

} // namespace bpftrace::ast
