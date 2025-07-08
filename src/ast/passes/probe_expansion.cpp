#include "ast/passes/probe_expansion.h"

#include "ast/visitor.h"
#include "bpftrace.h"
#include "util/wildcard.h"

namespace bpftrace::ast {

using ast::ExpansionType;

class ExpansionAnalyser : public Visitor<ExpansionAnalyser> {
public:
  ExpansionAnalyser(BPFtrace &bpftrace) : bpftrace_(bpftrace)
  {
  }
  void analyse(Program &program);

  using Visitor<ExpansionAnalyser>::visit;
  void visit(Probe &probe);
  void visit(AttachPoint &ap);
  void visit(Builtin &builtin);

private:
  Probe *probe_ = nullptr;

  BPFtrace &bpftrace_;
};

void ExpansionAnalyser::analyse(Program &program)
{
  visit(program);
}

void ExpansionAnalyser::visit(Probe &probe)
{
  probe_ = &probe;

  visit(probe.attach_points);
  visit(probe.pred);
  visit(probe.block);
}

void ExpansionAnalyser::visit(AttachPoint &ap)
{
  ExpansionType expansion = ExpansionType::NONE;

  switch (probetype(ap.provider)) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      // kprobe_multi does not support the "module:function" syntax so in case
      // a module is specified, always use full expansion
      if (util::has_wildcard(ap.target)) {
        expansion = ExpansionType::FULL;
      } else if (util::has_wildcard(ap.func)) {
        if (ap.target.empty() && bpftrace_.feature_->has_kprobe_multi())
          expansion = ExpansionType::MULTI;
        else
          expansion = ExpansionType::FULL;
      }
      break;

    case ProbeType::uprobe:
    case ProbeType::uretprobe:
      // As the C++ language supports function overload, a given function name
      // (without parameters) could have multiple matches even when no
      // wildcards are used.
      if (util::has_wildcard(ap.func) || util::has_wildcard(ap.target) ||
          ap.lang == "cpp") {
        if (bpftrace_.feature_->has_uprobe_multi())
          expansion = ExpansionType::MULTI;
        else
          expansion = ExpansionType::FULL;
      }
      break;

    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
    case ProbeType::rawtracepoint:
      if (util::has_wildcard(ap.target) || util::has_wildcard(ap.func))
        expansion = ExpansionType::FULL;
      break;

    case ProbeType::usdt:
      // Always fully expand USDT probes as they may access args
      if (util::has_wildcard(ap.target) || util::has_wildcard(ap.ns) ||
          ap.ns.empty() || util::has_wildcard(ap.func) ||
          bpftrace_.pid().has_value()) {
        expansion = ExpansionType::FULL;
      }
      break;

    case ProbeType::watchpoint:
      if (util::has_wildcard(ap.func))
        expansion = ExpansionType::FULL;
      break;

    case ProbeType::iter:
      if (util::has_wildcard(ap.func))
        expansion = ExpansionType::FULL;

    default:
      // No expansion support for the rest of the probe types
      break;
  }

  if (expansion != ExpansionType::NONE)
    ap.expansion = expansion;
}

void ExpansionAnalyser::visit(Builtin &builtin)
{
  if (!probe_)
    return;

  if (builtin.ident == "args") {
    for (auto *ap : probe_->attach_points) {
      if (probetype(ap->provider) == ProbeType::tracepoint) {
        ap->expansion = ExpansionType::FULL;
      }
    }
  } else if (builtin.ident == "probe") {
    for (auto *ap : probe_->attach_points)
      ap->expansion = ExpansionType::FULL;
  }
}

class SessionAnalyser : public Visitor<SessionAnalyser> {
public:
  explicit SessionAnalyser(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace)
  {
  }

  using Visitor<SessionAnalyser>::visit;
  void visit(Probe &probe);

  void analyse();

private:
  const ASTContext &ast_;
  const BPFtrace &bpftrace_;
};

void SessionAnalyser::analyse()
{
  visit(*ast_.root);
}

void SessionAnalyser::visit(Probe &probe)
{
  // If the probe has a single multi-expanded kprobe attach point, check if
  // there's another probe with a single multi-expanded kretprobe attach point
  // with the same target. If so, use session expansion if available.
  // Also, we do not allow predicates in any of the probes for now.
  if (probe.attach_points.size() == 1 &&
      probetype(probe.attach_points[0]->provider) == ProbeType::kprobe &&
      probe.pred == nullptr) {
    // Session probes use the same attach mechanism as multi probes so the
    // attach point must be multi-expanded.
    auto &ap = *probe.attach_points[0];
    if (ap.expansion != ExpansionType::MULTI)
      return;

    for (Probe *other_probe : ast_.root->probes) {
      // Other probe must also have a single multi-expanded attach point and no
      // predicate
      if (other_probe->attach_points.size() != 1 || other_probe->pred)
        continue;
      auto &other_ap = *other_probe->attach_points[0];
      if (probetype(other_ap.provider) != ProbeType::kretprobe ||
          other_ap.expansion != ExpansionType::MULTI) {
        continue;
      }

      if (ap.target == other_ap.target && ap.func == other_ap.func) {
        if (bpftrace_.feature_->has_kprobe_session()) {
          ap.expansion = ExpansionType::SESSION;
          ap.ret_probe = other_probe;
          other_ap.expansion = ExpansionType::SESSION;
        } else {
          return;
        }
      }
    }
  }
}

Pass CreateProbeExpansionPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &bpftrace) {
    ExpansionAnalyser analyser(bpftrace);
    analyser.analyse(*ast.root);
    SessionAnalyser sessions(ast, bpftrace);
    sessions.analyse();
  };

  return Pass::create("ProbeExpansion", fn);
}

} // namespace bpftrace::ast
