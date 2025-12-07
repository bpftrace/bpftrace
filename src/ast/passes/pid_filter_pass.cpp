#include "ast/passes/pid_filter_pass.h"
#include "ast/ast.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

namespace {

class PidFilterPass : public Visitor<PidFilterPass> {
public:
  explicit PidFilterPass(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace)
  {
  }

  using Visitor<PidFilterPass>::visit;
  void visit(Probe &probe);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
};

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
    // These probe types support passing the pid during attachment
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
    case ProbeType::watchpoint:
    case ProbeType::invalid:
    case ProbeType::iter:
    case ProbeType::profile:
    case ProbeType::software:
    case ProbeType::hardware:
    // We don't filter by pid at all for these special probes
    case ProbeType::interval:
    case ProbeType::special:
    case ProbeType::test:
    case ProbeType::benchmark:
      return false;
  }

  return false;
}

} // namespace

static BlockExpr *create_pid_filter(ASTContext &ast,
                                    int pid,
                                    BlockExpr *orig_block)
{
  auto *ret_block = ast.make_node<BlockExpr>(
      orig_block->loc,
      StatementList(
          { ast.make_node<Jump>(orig_block->loc, ast::JumpType::RETURN) }),
      ast.make_node<None>(orig_block->loc));

  return ast.make_node<BlockExpr>(
      orig_block->loc,
      StatementList({}),
      ast.make_node<IfExpr>(
          orig_block->loc,
          ast.make_node<Binop>(orig_block->loc,
                               ast.make_node<Builtin>(orig_block->loc, "pid"),
                               Operator::NE,
                               ast.make_node<Integer>(orig_block->loc, pid)),
          ret_block,
          orig_block));
}

void PidFilterPass::visit(Probe &probe)
{
  const auto pid = bpftrace_.pid();
  if (!pid.has_value()) {
    return;
  }

  for (AttachPoint *ap : probe.attach_points) {
    if (probe_needs_pid_filter(ap)) {
      probe.block = create_pid_filter(ast_, *pid, probe.block);
      return;
    }
  }
}

Pass CreatePidFilterPass()
{
  return Pass::create("PidFilter", [](ASTContext &ast, BPFtrace &b) {
    auto pid_filter = PidFilterPass(ast, b);
    pid_filter.visit(ast.root);
  });
};

} // namespace bpftrace::ast
