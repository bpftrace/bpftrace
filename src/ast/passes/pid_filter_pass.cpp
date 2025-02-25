#include "pid_filter_pass.h"

#include "ast/ast.h"

namespace bpftrace::ast {

Pass CreatePidFilterPass()
{
  auto fn = [](PassContext &ctx) {
    auto pid_filter = PidFilterPass(ctx.ast_ctx, ctx.b);
    pid_filter.analyse();
    return PassResult::Success();
  };

  return Pass("PidFilter", fn);
};

void PidFilterPass::analyse()
{
  visit(ctx_.root);
}

void PidFilterPass::visit(Probe &probe)
{
  bool needs_pid_filter = false;

  for (AttachPoint *ap : probe.attach_points) {
    if (bpftrace_.pid().has_value() && probe_needs_pid_filter(ap)) {
      needs_pid_filter = true;
    }
  }

  if (needs_pid_filter) {
    probe.block->stmts.insert(probe.block->stmts.begin(),
                              add_pid_filter(probe.loc));
  }
}

// If the probe can't filter by pid when attaching
// then we inject custom AST to filter by pid.
// Note: this doesn't work for AOT as the code has already
// been generated
bool PidFilterPass::probe_needs_pid_filter(AttachPoint *ap)
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

Statement *PidFilterPass::add_pid_filter(const location &loc)
{
  return ctx_.make_node<If>(
      ctx_.make_node<Binop>(ctx_.make_node<Builtin>("pid", loc),
                            Operator::NE,
                            ctx_.make_node<Integer>(bpftrace_.pid().value_or(0),
                                                    loc),
                            loc),
      ctx_.make_node<Block>(std::vector<Statement *>{ ctx_.make_node<Jump>(
                                JumpType::RETURN, loc) },
                            loc),
      ctx_.make_node<Block>(std::vector<Statement *>{}, loc),
      loc);
}

} // namespace bpftrace::ast
