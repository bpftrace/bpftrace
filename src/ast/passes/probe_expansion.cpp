#include "ast/passes/probe_expansion.h"

#include <algorithm>

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

private:
  std::unordered_map<AttachPoint *, ExpansionType> expansions;
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

class SessionExpander : public Visitor<SessionExpander> {
public:
  explicit SessionExpander(ASTContext &ast,
                           BPFtrace &bpftrace,
                           ExpansionResult &expansion_result)
      : ast_(ast), bpftrace_(bpftrace), expansion_result_(expansion_result)
  {
  }

  using Visitor<SessionExpander>::visit;
  void visit(Probe &probe);

  Probe expand(Probe &entry, Probe &exit);

private:
  Probe *find_matching_retprobe(Probe &probe);

  ASTContext &ast_;
  const BPFtrace &bpftrace_;
  ExpansionResult &expansion_result_;
};

Probe *SessionExpander::find_matching_retprobe(Probe &probe)
{
  ProbeList retprobes;
  AttachPoint *ap = probe.attach_points[0];
  // Search for a probe which:
  // - has a single kretprobe attach point
  // - attaches to the same target and function as probe
  // - is multi-expanded (session expansion uses the same attach mechanism)
  // - has no predicate
  std::ranges::copy_if(
      ast_.root->probes, std::back_inserter(retprobes), [&](Probe *other) {
        return other->attach_points.size() == 1 && other->pred == nullptr &&
               probetype(other->attach_points[0]->provider) ==
                   ProbeType::kretprobe &&
               expansion_result_.get_expansion(*other->attach_points[0]) ==
                   ExpansionType::MULTI &&
               other->attach_points[0]->target == ap->target &&
               other->attach_points[0]->func == ap->func;
      });

  // If there's not exactly one match, we don't know how to do session expansion
  if (retprobes.size() == 1)
    return retprobes[0];

  return nullptr;
}

void SessionExpander::visit(Probe &probe)
{
  // If the probe has a single multi-expanded kprobe attach point, check if
  // there's another probe with a single multi-expanded kretprobe attach point
  // with the same target. If so, perform session expansion by merging the two
  // probes together.
  // Currently, we don't allow predicates in either of the probes.
  if (probe.attach_points.size() == 1 &&
      probetype(probe.attach_points[0]->provider) == ProbeType::kprobe &&
      probe.pred == nullptr) {
    Probe *retprobe = find_matching_retprobe(probe);
    if (!retprobe)
      return;

    if (!bpftrace_.feature_->has_kprobe_session())
      return;

    AttachPointList attach_points = probe.attach_points;
    auto *if_cond = ast_.make_node<If>(
        ast_.make_node<Builtin>("__session_is_return",
                                Location(probe.block->loc)),
        retprobe->block,
        probe.block,
        Location(probe.block->loc));

    probe.block = ast_.make_node<Block>(std::vector<Statement>{ if_cond },
                                        Location(probe.block->loc));

    expansion_result_.set_expansion(*probe.attach_points[0],
                                    ExpansionType::SESSION);

    std::erase(ast_.root->probes, retprobe);
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

      case ExpansionType::SESSION:
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

    SessionExpander session_expander(ast, bpftrace, result);
    session_expander.visit(*ast.root);

    ProbeExpander expander(ast, bpftrace);
    expander.expand(std::move(result));
  };

  return Pass::create("ProbeExpansion", fn);
}

} // namespace bpftrace::ast
