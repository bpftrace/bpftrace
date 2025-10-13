#include <bpf/bpf.h>
#include <cassert>

#include "arch/arch.h"
#include "ast/passes/ap_expansion.h"
#include "ast/passes/probe_expansion.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "dwarf_parser.h"
#include "probe_matcher.h"
#include "tracepoint_format_parser.h"
#include "util/strings.h"

namespace bpftrace::ast {

namespace {

std::shared_ptr<Struct> get_args(BPFtrace &bpftrace,
                                 const ast::AttachPoint &ap,
                                 ProbeType probe_type,
                                 std::string func,
                                 std::string target,
                                 std::string &err)
{
  std::shared_ptr<Struct> args;
  if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
    args = bpftrace.btf_->resolve_args(
        func, probe_type == ProbeType::fexit, true, false, err);

  } else if (probe_type == ProbeType::rawtracepoint) {
    args = bpftrace.btf_->resolve_raw_tracepoint_args(func, err);
  } else if (probe_type == ProbeType::tracepoint) {
    auto struct_name = TracepointFormatParser::get_struct_name(ap);
    args = bpftrace.structs.Lookup(struct_name).lock();
    if (!args) {
      err = ("No type found for tracepoint args: " + struct_name);
    }
  } else { // uprobe
    Dwarf *dwarf = bpftrace.get_dwarf(target);
    if (dwarf) {
      args = dwarf->resolve_args(func);
    } else {
      err = ("No debuginfo found for " + target);
    }
  }
  return args;
}

class ArgsResolver : public Visitor<ArgsResolver> {
public:
  explicit ArgsResolver(ASTContext &ast,
                        BPFtrace &bpftrace,
                        ExpansionResult &ap_expansions,
                        std::unordered_set<ProbeType> probe_types)
      : ast_(ast),
        bpftrace_(bpftrace),
        ap_expansions_(ap_expansions),
        probe_types_(std::move(probe_types))
  {
  }

  using Visitor<ArgsResolver>::visit;
  void visit(Builtin &builtin);
  void visit(Probe &probe);

private:
  void resolve_args(Probe &probe);

  ASTContext &ast_;
  BPFtrace &bpftrace_;
  ExpansionResult &ap_expansions_;
  std::unordered_set<ProbeType> probe_types_;
  Probe *probe_ = nullptr;
};

class ProbeExpansion : public Visitor<ProbeExpansion> {
public:
  explicit ProbeExpansion(ASTContext &ast,
                          BPFtrace &bpftrace,
                          ExpansionResult &ap_expansions,
                          std::unordered_set<ProbeType> probe_types)
      : ast_(ast),
        bpftrace_(bpftrace),
        ap_expansions_(ap_expansions),
        probe_types_(std::move(probe_types))
  {
  }

  using Visitor<ProbeExpansion>::visit;
  void visit(Builtin &builtin);
  void visit(Program &prog);

private:
  void check_args(Probe &probe);

  ASTContext &ast_;
  BPFtrace &bpftrace_;
  ExpansionResult &ap_expansions_;
  std::unordered_set<ProbeType> probe_types_;
  Probe *probe_ = nullptr;
  bool needs_expansion_ = false;
};

} // namespace

void ArgsResolver::visit(Builtin &builtin)
{
  if (builtin.ident == "args" || builtin.ident == "__builtin_retval") {
    resolve_args(*probe_);
  }
}

void ArgsResolver::resolve_args(Probe &probe)
{
  for (auto *ap : probe.attach_points) {
    std::shared_ptr<Struct> probe_args;

    auto probe_type = probetype(ap->provider);
    if (!probe_types_.contains(probe_type)) {
      continue;
    }

    std::string err;
    if (ap_expansions_.get_expansion(*ap) != ExpansionType::NONE) {
      std::set<std::string> matches =
          bpftrace_.probe_matcher_->get_matches_for_ap(*ap);

      for (const auto &match : matches) {
        std::string func = match;
        std::string target = util::erase_prefix(func);
        probe_args = get_args(bpftrace_, *ap, probe_type, func, target, err);

        if (!probe_args) {
          continue;
        }
        // At this point the args should all match or there is only one
        // so we can break
        break;
      }
    } else {
      probe_args = get_args(
          bpftrace_, *ap, probe_type, ap->func, ap->target, err);
    }

    if (!probe_args) {
      ap->addError() << "Unable to get arguments for "
                     << probetypeName(probe_type) << ap->func << ": " << err;
      return;
    }

    bpftrace_.structs.Add(probe.args_typename(), std::move(probe_args));
  }
}

void ArgsResolver::visit(Probe &probe)
{
  probe_ = &probe;
  visit(probe.block);
}

void ProbeExpansion::visit(Builtin &builtin)
{
  if (builtin.ident == "__builtin_probe") {
    needs_expansion_ = true;
  } else if (builtin.ident == "args" || builtin.ident == "__builtin_retval") {
    check_args(*probe_);
  }
}

void ProbeExpansion::check_args(Probe &probe)
{
  std::shared_ptr<Struct> prev_probe_args;
  ProbeType prev_probe_type = ProbeType::invalid;

  for (auto *ap : probe.attach_points) {
    auto probe_type = probetype(ap->provider);
    if (prev_probe_type == ProbeType::invalid) {
      prev_probe_type = probe_type;
    } else if (prev_probe_type != probe_type) {
      // Mixed provider probes are always expanded but continue to check args
      needs_expansion_ = true;
    }

    if (!probe_types_.contains(probe_type)) {
      continue;
    }

    std::shared_ptr<Struct> probe_args;
    std::string err;

    if (ap_expansions_.get_expansion(*ap) != ExpansionType::NONE) {
      std::set<std::string> matches;

      // Find all the matches for the wildcard..
      try {
        matches = bpftrace_.probe_matcher_->get_matches_for_ap(*ap);
      } catch (const WildcardException &e) {
        probe.addError() << e.what();
        return;
      }

      // ... and check if they share same arguments and if they don't this probe
      // needs expansion
      for (const auto &match : matches) {
        // Both uprobes and fentry have a target (binary for uprobes, kernel
        // module for fentry).
        std::string func = match;
        std::string target = util::erase_prefix(func);

        std::shared_ptr<Struct> ap_args = get_args(
            bpftrace_, *ap, probe_type, func, target, err);
        if (!ap_args) {
          ap->addWarning() << probetypeName(probe_type) << ap->func << ": "
                           << err;
          continue;
        }

        if (!probe_args)
          probe_args = ap_args;
        else if (*ap_args != *probe_args) {
          needs_expansion_ = true;
        }
      }
    } else {
      probe_args = get_args(
          bpftrace_, *ap, probe_type, ap->func, ap->target, err);

      if (probe_type == ProbeType::uprobe && probe_args &&
          probe_args->fields.size() >= arch::Host::arguments().size()) {
        ap->addError() << "\'args\' builtin is not supported for "
                       << "probes with stack-passed arguments.";
      }
    }

    if (!probe_args) {
      ap->addError() << "Unable to get arguments for "
                     << probetypeName(probe_type) << ap->func << ": " << err;
      return;
    }

    err.clear();

    if (!prev_probe_args) {
      prev_probe_args = probe_args;
    } else if (*prev_probe_args != *probe_args) {
      needs_expansion_ = true;
    }
  }
}

void ProbeExpansion::visit(Program &prog)
{
  ProbeList new_probe_list;

  for (auto *probe : prog.probes) {
    probe_ = probe;
    needs_expansion_ = false;
    visit(probe_->block);
    if (!needs_expansion_) {
      new_probe_list.emplace_back(probe);
      continue;
    }

    for (auto *ap : probe->attach_points) {
      // Only one per probe
      AttachPointList new_ap;
      new_ap.emplace_back(ap);

      auto *new_probe = ast_.make_node<Probe>(
          std::move(new_ap),
          clone(ast_, probe->block, probe->block->loc),
          Location(probe->loc));
      new_probe_list.emplace_back(new_probe);
    }
  }

  prog.probes = std::move(new_probe_list);
}

Pass CreateProbeExpansionPass(std::unordered_set<ProbeType> &&probe_types)
{
  auto fn = [pt = std::move(probe_types)](ASTContext &ast,
                                          BPFtrace &b,
                                          ExpansionResult &ap_expansions) {
    ProbeExpansion analyser(ast, b, ap_expansions, pt);
    analyser.visit(ast.root);

    if (!ast.diagnostics().ok()) {
      // Something went wrong, no args resolving
      return;
    }

    ArgsResolver resolver(ast, b, ap_expansions, pt);
    resolver.visit(ast.root);
  };

  return Pass::create("ProbeExpansion", fn);
};

} // namespace bpftrace::ast
