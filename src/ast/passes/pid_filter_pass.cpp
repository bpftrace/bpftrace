#include "pid_filter_pass.h"

#include "ast/ast.h"

namespace bpftrace::ast {

// If the probe can't filter by pid when attaching
// then we inject custom AST to filter by pid.
// Note: this doesn't work for AOT as the code has already
// been generated
bool probe_needs_pid_filter(AttachPoint *ap)
{
  ProbeType type = probetype(ap->provider);

  switch (type) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
    case ProbeType::rawtracepoint:
      return true;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
    case ProbeType::invalid:
    case ProbeType::iter:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::software:
    case ProbeType::hardware:
    // We don't filter by pid for BEGIN/END probes
    case ProbeType::special:
      return false;
  }

  return false;
}

Statement *create_pid_filter(ASTContext &ctx, int pid, const location &loc)
{
  return ctx.make_node<If>(
      ctx.make_node<Binop>(ctx.make_node<Builtin>("pid", loc),
                           Operator::NE,
                           ctx.make_node<Integer>(pid, loc),
                           loc),
      ctx.make_node<Block>(std::vector<Statement *>{ ctx.make_node<Jump>(
                               JumpType::RETURN, loc) },
                           loc),
      ctx.make_node<Block>(std::vector<Statement *>{}, loc),
      loc);
}

void PidFilterPass::visit(Probe &probe)
{
  const auto pid = bpftrace_.pid();
  if (!pid.has_value()) {
    return;
  }

  for (AttachPoint *ap : probe.attach_points) {
    if (probe_needs_pid_filter(ap)) {
      probe.block->stmts.insert(probe.block->stmts.begin(),
                                create_pid_filter(ctx_, *pid, probe.loc));
      return;
    }
  }
}

void PidFilterPass::analyse()
{
  visit(ctx_.root);
}

Pass CreatePidFilterPass()
{
  auto fn = [](PassContext &ctx) {
    auto pid_filter = PidFilterPass(ctx.ast_ctx, ctx.b);
    pid_filter.analyse();
  };

  return Pass("PidFilter", fn);
};

} // namespace bpftrace::ast
