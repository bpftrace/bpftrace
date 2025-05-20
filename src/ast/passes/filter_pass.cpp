#include "ast/passes/filter_pass.h"
#include "ast/ast.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

namespace {

class FilterPass : public Visitor<FilterPass> {
public:
  explicit FilterPass(ASTContext &ast, const FilterInputs &inputs)
      : ast_(ast), inputs_(inputs)
  {
  }

  using Visitor<FilterPass>::visit;
  void visit(Probe &probe);

private:
  ASTContext &ast_;
  const FilterInputs inputs_;
};

// We only needs filters for probes that may be associated with some relevant
// userspace process. This is not generally the case for generic hardware &
// software performance counters, for example.
bool probe_needs_filter(AttachPoint *ap)
{
  ProbeType type = probetype(ap->provider);

  switch (type) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
    case ProbeType::rawtracepoint:
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      return true;
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

} // namespace

static Statement create_pid_filter(ASTContext &ast,
                                   pid_t pid,
                                   const Location &loc)
{
  return ast.make_node<If>(
      ast.make_node<Binop>(ast.make_node<Builtin>("pid", Location(loc)),
                           Operator::NE,
                           ast.make_node<Integer>(pid, Location(loc)),
                           Location(loc)),
      ast.make_node<Block>(std::vector<Statement>{ ast.make_node<Jump>(
                               JumpType::RETURN, Location(loc)) },
                           Location(loc)),
      ast.make_node<Block>(std::vector<Statement>{}, Location(loc)),
      Location(loc));
}

static Statement create_cgroup_filter(ASTContext &ast,
                                      uint64_t cgroup_id,
                                      const Location &loc)
{
  std::vector<Expression> args = { ast.make_node<Integer>(cgroup_id,
                                                          Location(loc)) };
  return ast.make_node<If>(
      ast.make_node<Binop>(
          ast.make_node<Call>("__in_cgroup", std::move(args), Location(loc)),
          Operator::EQ,
          ast.make_node<Integer>(0, Location(loc)),
          Location(loc)),
      ast.make_node<Block>(std::vector<Statement>{ ast.make_node<Jump>(
                               JumpType::RETURN, Location(loc)) },
                           Location(loc)),
      ast.make_node<Block>(std::vector<Statement>{}, Location(loc)),
      Location(loc));
}

void FilterPass::visit(Probe &probe)
{
  for (AttachPoint *ap : probe.attach_points) {
    if (!probe_needs_filter(ap)) {
      continue;
    }
    if (inputs_.pid) {
      probe.block->stmts.insert(
          probe.block->stmts.begin(),
          create_pid_filter(ast_, *inputs_.pid, probe.loc));
    }
    if (inputs_.cgroup_id) {
      probe.block->stmts.insert(
          probe.block->stmts.begin(),
          create_cgroup_filter(ast_, *inputs_.cgroup_id, probe.loc));
    }
    return; // Modified the probe.
  }
}

Pass CreateFilterPass(const FilterInputs &inputs)
{
  return Pass::create("Filter", [inputs](ASTContext &ast) {
    auto filter = FilterPass(ast, inputs);
    filter.visit(ast.root);
  });
};

} // namespace bpftrace::ast
