#include "portability_analyser.h"

#include "log.h"
#include "types.h"

namespace bpftrace {
namespace ast {

PortabilityAnalyser::PortabilityAnalyser(Node *root, std::ostream &out)
    : root_(root), out_(out)
{
}

int PortabilityAnalyser::analyse()
{
  Visit(*root_);

  std::string errors = err_.str();
  if (!errors.empty())
  {
    out_ << errors;
    return 1;
  }

  return 0;
}

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
  LOG(ERROR, param.loc, err_)
      << "AOT does not yet support positional parameters";
}

void PortabilityAnalyser::visit(Builtin &builtin)
{
  // `struct task_struct` is unstable across kernel versions and configurations.
  // This makes it inherently unportable. We must block it until we support
  // field access relocations.
  if (builtin.ident == "curtask")
  {
    LOG(ERROR, builtin.loc, err_)
        << "AOT does not yet support accessing `curtask`";
  }
}

void PortabilityAnalyser::visit(Call &call)
{
  if (call.vargs)
  {
    for (Expression *expr : *call.vargs)
      Visit(*expr);
  }

  // kaddr() and uaddr() both resolve symbols -> address during codegen and
  // embeds the values into the bytecode. For AOT to support kaddr()/uaddr(),
  // the addresses must be resolved at runtime and fixed up during load time.
  //
  // cgroupid can vary across systems just like how a process does not
  // necessarily share the same PID across multiple systems. cgroupid() is also
  // resolved during codegen and the value embedded into the bytecode.  For AOT
  // to support cgroupid(), the cgroupid must be resolved at runtime and fixed
  // up during load time.
  if (call.func == "kaddr" || call.func == "uaddr" || call.func == "cgroupid")
  {
    LOG(ERROR, call.loc, err_)
        << "AOT does not yet support " << call.func << "()";
  }
}

void PortabilityAnalyser::visit(Cast &cast)
{
  Visit(*cast.expr);

  // The goal here is to block arbitrary field accesses but still allow `args`
  // access. `args` for tracepoint is fairly stable and should be considered
  // portable. `args` for k[ret]funcs are type checked by the kernel and may
  // also be considered stable. For AOT to fully support field accesses, we
  // need to relocate field access at runtime.
  LOG(ERROR, cast.loc, err_) << "AOT does not yet support struct casts";
}

void PortabilityAnalyser::visit(AttachPoint &ap)
{
  auto type = probetype(ap.provider);

  // USDT probes require analyzing a USDT enabled binary for precise offsets
  // and argument information. This analyzing is currently done during codegen
  // and offsets and type information is embedded into the bytecode. For AOT
  // support, this analyzing must be done during runtime and fixed up during
  // load time.
  if (type == ProbeType::usdt)
  {
    LOG(ERROR, ap.loc, err_) << "AOT does not yet support USDT probes";
  }
  // While userspace watchpoint probes are technically portable from codegen
  // point of view, they require a PID or path via cmdline to resolve address.
  // watchpoint probes are also API-unstable and need a further change
  // (see https://github.com/iovisor/bpftrace/issues/1683).
  //
  // So disable for now and re-evalulate at another point.
  else if (type == ProbeType::watchpoint || type == ProbeType::asyncwatchpoint)
  {
    LOG(ERROR, ap.loc, err_) << "AOT does not yet support watchpoint probes";
  }
}

Pass CreatePortabilityPass()
{
  auto fn = [](Node &n, PassContext &__attribute__((unused))) {
    PortabilityAnalyser analyser{ &n };
    if (analyser.analyse())
      return PassResult::Error("");

    return PassResult::Success();
  };

  return Pass("PortabilityAnalyser", fn);
}

} // namespace ast
} // namespace bpftrace
