#include "codegen_resources.h"

#include "ast/async_event_types.h"
#include "struct.h"
#include "types.h"

namespace bpftrace::ast {

CodegenResourceAnalyser::CodegenResourceAnalyser(
    Program &program,
    const ::bpftrace::Config &config)
    : program_(program), config_(config)
{
}

CodegenResources CodegenResourceAnalyser::analyse()
{
  Visit(program_);
  return std::move(resources_);
}

void CodegenResourceAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "elapsed") {
    resources_.needs_elapsed_map = true;
  } else if (builtin.ident == "kstack" || builtin.ident == "ustack") {
    resources_.stackid_maps.insert(
        StackType{ .mode = config_.get(ConfigKeyStackMode::default_) });
  }
}

void CodegenResourceAnalyser::visit(Call &call)
{
  Visitor::visit(call);

  if (call.func == "join") {
    resources_.needs_join_map = true;
  } else if (call.func == "kstack" || call.func == "ustack") {
    resources_.stackid_maps.insert(call.type.stack_type);
  }
}

} // namespace bpftrace::ast
