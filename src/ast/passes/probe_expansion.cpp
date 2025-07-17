#include "ast/passes/probe_expansion.h"

#include "ast/ast.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"
#include "util/wildcard.h"

namespace bpftrace::ast {

using ast::ExpansionType;

class ExpansionResult {
public:
  ExpansionResult() = default;
  ExpansionResult(const ExpansionResult &) = delete;
  ExpansionResult &operator=(const ExpansionResult &) = delete;
  ExpansionResult(ExpansionResult &&) = default;
  ExpansionResult &operator=(ExpansionResult &&) = default;

  void set_expansion(AttachPoint &ap, ExpansionType type)
  {
    expansions[&ap] = type;
  }
  ExpansionType get_expansion(AttachPoint &ap)
  {
    auto exp = expansions.find(&ap);
    if (exp == expansions.end())
      return ExpansionType::NONE;
    return exp->second;
  }
  void set_session_ret_probe(AttachPoint &ap, Probe &ret_probe)
  {
    session_ret_probes[&ap] = &ret_probe;
  }
  Probe &get_session_ret_probe(AttachPoint &ap)
  {
    auto it = session_ret_probes.find(&ap);
    if (it == session_ret_probes.end()) {
      LOG(BUG) << "Requesting return probe for non-session attach-point";
    }
    return *it->second;
  }

private:
  std::unordered_map<AttachPoint *, ExpansionType> expansions;
  std::unordered_map<AttachPoint *, Probe *> session_ret_probes;
};

class ExpansionAnalyser : public Visitor<ExpansionAnalyser> {
public:
  ExpansionAnalyser(BPFtrace &bpftrace) : bpftrace_(bpftrace)
  {
  }
  ExpansionResult analyse(Program &program);

  using Visitor<ExpansionAnalyser>::visit;
  void visit(Probe &probe);
  void visit(AttachPoint &ap);
  void visit(Builtin &builtin);

private:
  ExpansionResult result_;
  Probe *probe_ = nullptr;

  BPFtrace &bpftrace_;
};

ExpansionResult ExpansionAnalyser::analyse(Program &program)
{
  visit(program);
  return std::move(result_);
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
    case ProbeType::fexit: {
      if (ap.target == "bpf") {
        if (!ap.bpf_prog_id || util::has_wildcard(ap.func)) {
          expansion = ExpansionType::FULL;
        }
        break;
      }
      [[fallthrough]];
    }
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
    result_.set_expansion(ap, expansion);
}

void ExpansionAnalyser::visit(Builtin &builtin)
{
  if (!probe_)
    return;

  if (builtin.ident == "probe") {
    for (auto *ap : probe_->attach_points)
      result_.set_expansion(*ap, ExpansionType::FULL);
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

  ExpansionResult analyse(ExpansionResult result);

private:
  ExpansionResult result_;

  const ASTContext &ast_;
  const BPFtrace &bpftrace_;
};

ExpansionResult SessionAnalyser::analyse(ExpansionResult result)
{
  result_ = std::move(result);
  visit(*ast_.root);
  return std::move(result_);
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
    if (result_.get_expansion(ap) != ExpansionType::MULTI)
      return;

    for (Probe *other_probe : ast_.root->probes) {
      // Other probe must also have a single multi-expanded attach point and no
      // predicate
      if (other_probe->attach_points.size() != 1 || other_probe->pred)
        continue;
      auto &other_ap = *other_probe->attach_points[0];
      if (probetype(other_ap.provider) != ProbeType::kretprobe ||
          result_.get_expansion(other_ap) != ExpansionType::MULTI) {
        continue;
      }

      if (ap.target == other_ap.target && ap.func == other_ap.func) {
        if (bpftrace_.feature_->has_kprobe_session()) {
          result_.set_expansion(ap, ExpansionType::SESSION);
          result_.set_expansion(other_ap, ExpansionType::SESSION);
          result_.set_session_ret_probe(ap, *other_probe);
        } else {
          return;
        }
      }
    }
  }
}

class ProbeExpander : public Visitor<ProbeExpander> {
public:
  ProbeExpander(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace)
  {
  }

  void expand(ExpansionResult result);

  using Visitor<ProbeExpander>::visit;
  void visit(Program &prog);
  void visit(AttachPointList &aps);

private:
  ExpansionResult result_;
  uint64_t probe_count_ = 0;

  ASTContext &ast_;
  BPFtrace &bpftrace_;
};

void ProbeExpander::expand(ExpansionResult result)
{
  result_ = std::move(result);
  visit(*ast_.root);
}

void ProbeExpander::visit(Program &prog)
{
  Visitor<ProbeExpander>::visit(prog);

  prog.clear_empty_probes();
}

void ProbeExpander::visit(AttachPointList &aps)
{
  const auto max_bpf_progs = bpftrace_.config_->max_bpf_progs;

  AttachPointList new_aps;
  for (auto *ap : aps) {
    auto expansion = result_.get_expansion(*ap);
    switch (expansion) {
      case ExpansionType::FULL: {
        auto matches = bpftrace_.probe_matcher_->get_matches_for_ap(*ap);

        probe_count_ += matches.size();
        if (probe_count_ > max_bpf_progs) {
          auto &err = ap->addError();
          err << "Your program is trying to generate more than "
              << std::to_string(probe_count_)
              << " BPF programs, which exceeds the current limit of "
              << std::to_string(max_bpf_progs);
          err.addHint() << "You can increase the limit through the "
                           "BPFTRACE_MAX_BPF_PROGS "
                           "environment variable.";
          return;
        }

        for (const auto &match : matches) {
          new_aps.push_back(ap->create_expansion_copy(ast_, match));
        }
        break;
      }

      case ExpansionType::SESSION: {
        if (probetype(ap->provider) == ProbeType::kprobe) {
          ap->ret_probe = &result_.get_session_ret_probe(*ap);
        }
        [[fallthrough]];
      }
      case ExpansionType::MULTI:
      case ExpansionType::NONE: {
        ap->expansion = expansion;
        new_aps.push_back(ap);
        break;
      }
    }
  }

  aps = new_aps;
}

Pass CreateProbeExpansionPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &bpftrace) {
    ExpansionAnalyser analyser(bpftrace);
    auto result = analyser.analyse(*ast.root);

    SessionAnalyser sessions(ast, bpftrace);
    result = sessions.analyse(std::move(result));

    ProbeExpander expander(ast, bpftrace);
    expander.expand(std::move(result));
  };

  return Pass::create("ProbeExpansion", fn);
}

} // namespace bpftrace::ast
