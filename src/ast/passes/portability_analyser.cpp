#include <cstdlib>

#include "ast/passes/portability_analyser.h"
#include "ast/visitor.h"
#include "types.h"

namespace bpftrace::ast {

namespace {

// Checks if a script uses any non-portable bpftrace features that AOT
// cannot handle.
//
// Over time, we expect to relax these restrictions as AOT supports more
// features.
class PortabilityAnalyser : public Visitor<PortabilityAnalyser> {
public:
  using Visitor<PortabilityAnalyser>::visit;
  void visit(PositionalParameter &param);
  void visit(Identifier &ident);
  void visit(Call &call);
  void visit(Cast &cast);
};

void PortabilityAnalyser::visit(PositionalParameter &param)
{
  // Positional params are only known at runtime. Currently, codegen directly
  // embeds positional params into the bytecode but that does not work for AOT.
  //
  // In theory we could allow positional params for AOT and just embed the
  // values into the bytecode but there's really no point to that as:
  //
  //   * that would mislead the user into thinking there's positional param
  //   support
  //   * the user can just hard code the values into their script
  param.addError() << "AOT does not yet support positional parameters";
}

void PortabilityAnalyser::visit(Identifier &identifier)
{
  // `struct task_struct` is unstable across kernel versions and configurations.
  // This makes it inherently unportable. We must block it until we support
  // field access relocations.
  if (identifier.ident == "curtask") {
    identifier.addWarning() << "AOT does not yet support relocating `curtask`";
  }
}

void PortabilityAnalyser::visit(Call &call)
{
  for (auto &expr : call.vargs)
    visit(expr);

  // kaddr() and __builtin_uaddr() both resolve symbols -> address during
  // codegen and embeds the values into the bytecode. For AOT to support
  // kaddr()/__builtin_uaddr(), the addresses must be resolved at runtime
  // and fixed up during load time.
  //
  // cgroupid can vary across systems just like how a process does not
  // necessarily share the same PID across multiple systems. cgroupid() is also
  // resolved during codegen and the value embedded into the bytecode.  For AOT
  // to support cgroupid(), the cgroupid must be resolved at runtime and fixed
  // up during load time.
  if (call.func == "kaddr" || call.func == "__builtin_uaddr" ||
      call.func == "cgroupid") {
    call.addError() << "AOT does not yet support " << call.func << "()";
  }
}

void PortabilityAnalyser::visit(Cast &cast)
{
  visit(cast.expr);

  // The goal here is to block arbitrary field accesses but still allow `args`
  // access. `args` for tracepoint is fairly stable and should be considered
  // portable. `args` for k[ret]funcs are type checked by the kernel and may
  // also be considered stable. For AOT to fully support field accesses, we
  // need to relocate field access at runtime.
  cast.addError() << "AOT does not yet support struct casts";
}

} // namespace

Pass CreatePortabilityPass()
{
  auto fn = [](ASTContext &ast) {
    PortabilityAnalyser analyser;
    analyser.visit(ast.root);
    if (!ast.diagnostics().ok()) {
      // Used by runtime test framework to know when to skip an AOT test
      if (std::getenv("__BPFTRACE_NOTIFY_AOT_PORTABILITY_DISABLED"))
        std::cout << "__BPFTRACE_NOTIFY_AOT_PORTABILITY_DISABLED" << std::endl;
    }
  };

  return Pass::create("PortabilityAnalyser", fn);
}

} // namespace bpftrace::ast
