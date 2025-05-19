#include "ast/passes/filter_pass.h"
#include "ast/ast.h"
#include "ast/passes/resolve_imports.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class FilterPass : public Visitor<FilterPass> {
public:
  explicit FilterPass(ASTContext &ast,
                      Imports &imports,
                      const FilterInputs &inputs)
      : ast_(ast), imports_(imports), inputs_(inputs) {};

  using Visitor<FilterPass>::visit;
  void visit(Probe &probe);

private:
  ASTContext &ast_;
  Imports &imports_;
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
      return true;
    // These probe types support passing the pid during attachment
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
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

static BlockExpr *create_cgroup_filter(ASTContext &ast,
                                       uint64_t cgroup_id,
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
          ast.make_node<Unop>(
              orig_block->loc,
              ast.make_node<Call>(orig_block->loc,
                                  "in_cgroup",
                                  std::vector<Expression>{
                                      ast.make_node<Integer>(orig_block->loc,
                                                             cgroup_id) }),
              Operator::LNOT),
          ret_block,
          orig_block));
}

void FilterPass::visit(Probe &probe)
{
  bool pid_applied = false;
  bool cgroup_applied = false;
  for (AttachPoint *ap : probe.attach_points) {
    if (inputs_.pid && probe_needs_filter(ap) && !pid_applied) {
      probe.block = create_pid_filter(ast_, *inputs_.pid, probe.block);
      pid_applied = true;
    }
    if (inputs_.cgroup_id && probe_needs_filter(ap) && !cgroup_applied) {
      probe.block = create_cgroup_filter(ast_, *inputs_.cgroup_id, probe.block);
      cgroup_applied = true;
      // We need to ensure that the `in_cgroup` function is available.
      auto ok = imports_.import_any(*ast_.root, "stdlib/cgroups.bt");
      if (!ok) {
        ap->addError() << "Unable to filter on cgroup: " << ok.takeError();
      }
    }
  }
}

Pass CreateFilterPass(const FilterInputs &inputs)
{
  return Pass::create("Filter", [inputs](ASTContext &ast, Imports &imports) {
    if (inputs.pid || inputs.cgroup_id) {
      auto filter = FilterPass(ast, imports, inputs);
      filter.visit(ast.root);
    }
  });
};

} // namespace bpftrace::ast
