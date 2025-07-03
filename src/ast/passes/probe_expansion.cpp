#include "ast/passes/probe_expansion.h"

#include "ast/visitor.h"
#include "bpftrace.h"
#include "util/wildcard.h"

namespace bpftrace::ast {

using ast::ExpansionType;

class ExpansionAnalyser : public Visitor<ExpansionAnalyser> {
public:
  ExpansionAnalyser(BPFtrace &bpftrace, bool listing)
      : bpftrace_(bpftrace), listing_(listing)
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
  bool listing_;
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
      if (util::has_wildcard(ap.func)) {
        if (listing_)
          expansion = ExpansionType::FULL;
        else
          ap.addError() << "iter probe type does not support wildcards";
      }

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

Pass CreateProbeExpansionPass(bool listing)
{
  auto fn = [listing](ASTContext &ast, BPFtrace &bpftrace) {
    ExpansionAnalyser analyser(bpftrace, listing);
    analyser.analyse(*ast.root);
  };

  return Pass::create("ProbeExpansion", fn);
}

} // namespace bpftrace::ast
