#include "ast/passes/ap_probe_expansion.h"

#include <algorithm>

#include "ast/passes/attachpoint_passes.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "probe_matcher.h"
#include "util/wildcard.h"

namespace bpftrace::ast {

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

    case ProbeType::iter:
      if (util::has_wildcard(ap.func))
        expansion = ExpansionType::FULL;

    default:
      // No expansion support for the rest of the probe types.
      break;
  }

  if (expansion != ExpansionType::NONE)
    result_.set_expansion(ap, expansion);
}

void ExpansionAnalyser::visit(Builtin &builtin)
{
  if (!probe_)
    return;

  if (builtin.ident == "__builtin_probe") {
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
  std::ranges::copy_if(
      ast_.root->probes, std::back_inserter(retprobes), [&](Probe *other) {
        return other->attach_points.size() == 1 &&
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
  if (probe.attach_points.size() == 1 &&
      probetype(probe.attach_points[0]->provider) == ProbeType::kprobe) {
    Probe *retprobe = find_matching_retprobe(probe);
    if (!retprobe)
      return;

    if (!bpftrace_.feature_->has_kprobe_session())
      return;

    AttachPointList attach_points = probe.attach_points;
    auto *expr = ast_.make_node<IfExpr>(
        probe.block->loc,
        ast_.make_node<Call>(probe.block->loc,
                             "__session_is_return",
                             ExpressionList{}),
        retprobe->block,
        probe.block);
    auto *stmt = ast_.make_node<ExprStatement>(probe.block->loc, expr);

    probe.block = ast_.make_node<BlockExpr>(probe.block->loc,
                                            StatementList({ stmt }),
                                            ast_.make_node<None>(
                                                probe.block->loc));

    expansion_result_.set_expansion(*probe.attach_points[0],
                                    ExpansionType::SESSION);

    std::erase(ast_.root->probes, retprobe);
  }
}

class ProbeAndApExpander : public Visitor<ProbeAndApExpander> {
public:
  ProbeAndApExpander(ASTContext &ast,
                     BPFtrace &bpftrace,
                     FunctionInfo &func_info,
                     ExpansionResult &result)
      : ast_(ast),
        bpftrace_(bpftrace),
        func_info_(func_info),
        result_(result),
        probe_matcher_(&bpftrace,
                       func_info.kernel_info(),
                       func_info.user_info())
  {
  }

  void expand();

  using Visitor<ProbeAndApExpander>::visit;
  void visit(Program &prog);
  void visit(AttachPointList &aps);

private:
  uint64_t probe_count_ = 0;

  ASTContext &ast_;
  BPFtrace &bpftrace_;
  FunctionInfo &func_info_;
  ExpansionResult &result_;
  ProbeMatcher probe_matcher_;
};

void ProbeAndApExpander::expand()
{
  visit(*ast_.root);
}

void ProbeAndApExpander::visit(Program &prog)
{
  // Expand attachpoints first.
  Visitor<ProbeAndApExpander>::visit(prog);

  // Expand probes.
  ProbeList new_probe_list;
  for (auto *probe : prog.probes) {
    if (probe->attach_points.size() < 2) {
      new_probe_list.emplace_back(probe);
    } else {
      for (auto *ap : probe->attach_points) {
        auto *new_probe = ast_.make_node<Probe>(
            probe->loc,
            AttachPointList{ ap },
            clone(ast_, probe->block->loc, probe->block));
        new_probe_list.emplace_back(new_probe);
      }
    }
  }

  prog.probes = std::move(new_probe_list);
}

void ProbeAndApExpander::visit(AttachPointList &aps)
{
  const auto max_bpf_progs = bpftrace_.config_->max_bpf_progs;

  AttachPointList new_aps;
  for (auto *ap : aps) {
    auto probe_type = probetype(ap->provider);
    auto expansion = result_.get_expansion(*ap);
    switch (expansion) {
      case ExpansionType::FULL: {
        auto matches = probe_matcher_.get_matches_for_ap(*ap);

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
      case ExpansionType::MULTI: {
        auto matches = probe_matcher_.get_matches_for_ap(*ap);
        if (util::has_wildcard(ap->target)) {
          // If we have a wildcard in the target path, we need to generate one
          // attach point per expanded target
          assert(probe_type == ProbeType::uprobe ||
                 probe_type == ProbeType::uretprobe);

          std::unordered_map<std::string, AttachPoint *> new_aps_by_target;
          for (const auto &func : matches) {
            auto *match_ap = ap->create_expansion_copy(ast_, func);
            // Reset the original (possibly wildcarded) function name
            auto expanded_func = match_ap->func;
            match_ap->func = ap->func;

            auto new_ap = new_aps_by_target.emplace(match_ap->target, match_ap);
            result_.add_expanded_func(*new_ap.first->second,
                                      match_ap->target + ":" + expanded_func);
          }
          for (auto &[_, new_ap] : new_aps_by_target)
            new_aps.push_back(std::move(new_ap));
        } else if (!matches.empty()) {
          result_.set_expanded_funcs(*ap, std::move(matches));
          new_aps.push_back(ap);
        }
        break;
      }
      case ExpansionType::NONE: {
        auto pt = probetype(ap->provider);

        if (pt == ProbeType::kprobe || pt == ProbeType::kretprobe) {
          // Construct a string containing "module:function."
          // Also log a warning or throw an error if the module doesn't exist,
          // before attempting to attach.
          // Note that we do not pass vmlinux, if it is specified.
          const std::string &funcname = ap->func;
          const std::string &modname = ap->target;
          if ((!modname.empty()) && modname != "vmlinux") {
            if (!func_info_.kernel_info().is_module_loaded(modname)) {
              ap->addError() << "specified module " + modname + " in probe " +
                                    ap->provider + ":" + modname + ":" +
                                    funcname + " is not loaded.";
            }
          }
        }

        auto matches = probe_matcher_.get_matches_for_ap(*ap);
        // Filter out unnecessary probes, as they may not be missing.
        if (matches.empty() && (pt != ProbeType::watchpoint)) {
          const auto missing_probes = bpftrace_.config_->missing_probes;
          std::string msg = "No matches for " +
                            probetypeName(probetype(ap->provider)) + " " +
                            (ap->target.empty() ? "" : ap->target + ":") +
                            ap->func;
          if (missing_probes == ConfigMissingProbes::warn) {
            ap->addWarning() << msg << ". Skipping.";
          } else if (missing_probes == ConfigMissingProbes::error) {
            ap->addError() << msg << ".";
          }
        } else {
          new_aps.push_back(ap);
        }
        break;
      }
    }
  }

  aps = new_aps;
}

Pass CreateProbeAndApExpansionPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &bpftrace, FunctionInfo &func_info) {
    ExpansionAnalyser analyser(bpftrace);
    auto result = analyser.analyse(*ast.root);

    SessionExpander session_expander(ast, bpftrace, result);
    session_expander.visit(*ast.root);

    ProbeAndApExpander expander(ast, bpftrace, func_info, result);
    expander.expand();

    return result;
  };

  return Pass::create("ProbeAndApExpansion", fn);
}

} // namespace bpftrace::ast
