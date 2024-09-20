#include "codegen_resources.h"

#include "ast/async_event_types.h"
#include "struct.h"
#include "types.h"

namespace bpftrace::ast {

CodegenResourceAnalyser::CodegenResourceAnalyser(
    Node *root,
    const ::bpftrace::Config &config)
    : config_(config), root_(root)
{
}

CodegenResources CodegenResourceAnalyser::analyse()
{
  Visit(*root_);
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
  } else if (call.func == "str" || call.func == "buf" || call.func == "path") {
    resources_.str_buffers++;
  } else if (call.func == "kstack" || call.func == "ustack") {
    resources_.stackid_maps.insert(call.type.stack_type);
  }
}

void CodegenResourceAnalyser::visit(Ternary &ternary)
{
  Visitor::visit(ternary);

  // Codegen cannot use a phi node for ternary string b/c strings can be of
  // differing lengths and phi node wants identical types. So we have to
  // allocate a result temporary, but not on the stack b/c a big string would
  // blow it up. So we need a scratch buffer for it.
  if (ternary.type.IsStringTy())
    resources_.str_buffers++;
}

} // namespace bpftrace::ast
