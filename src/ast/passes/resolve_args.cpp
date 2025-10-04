#include <bpf/bpf.h>
#include <cassert>

#include "arch/arch.h"
#include "ast/passes/probe_expansion.h"
#include "ast/passes/resolve_args.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "dwarf_parser.h"
#include "probe_matcher.h"
#include "tracepoint_format_parser.h"
#include "util/strings.h"

namespace bpftrace::ast {

namespace {

class ArgsResolver : public Visitor<ArgsResolver> {
public:
  explicit ArgsResolver(BPFtrace &bpftrace,
                        ExpansionResult &expansions,
                        std::unordered_set<ProbeType> probe_types)
      : bpftrace_(bpftrace),
        expansions_(expansions),
        probe_types_(std::move(probe_types))
  {
  }

  using Visitor<ArgsResolver>::visit;
  void visit(Builtin &builtin);
  void visit(Probe &probe);

private:
  void resolve_args(Probe &probe);

  ProbeType probe_type_;
  BPFtrace &bpftrace_;
  ExpansionResult &expansions_;
  std::unordered_set<ProbeType> probe_types_;
  Probe *probe_ = nullptr;
};

} // namespace

void ArgsResolver::visit(Builtin &builtin)
{
  if (builtin.ident == "args") {
    if (!probe_)
      return;
    resolve_args(*probe_);
    return;
  } else if (builtin.ident == "__builtin_retval") {
    if (!probe_)
      return;
    resolve_args(*probe_);
  }
}

void ArgsResolver::resolve_args(Probe &probe)
{
  for (auto *ap : probe.attach_points) {
    // load probe arguments into a special record type "struct <probename>_args"
    std::shared_ptr<Struct> probe_args;

    auto probe_type = probetype(ap->provider);
    if (!probe_types_.contains(probe_type)) {
      continue;
    }

    if (expansions_.get_expansion(*ap) != ExpansionType::NONE) {
      std::set<std::string> matches;

      // Find all the matches for the wildcard..
      try {
        matches = bpftrace_.probe_matcher_->get_matches_for_ap(*ap);
      } catch (const WildcardException &e) {
        probe.addError() << e.what();
        return;
      }

      // ... and check if they share same arguments.

      std::shared_ptr<Struct> ap_args;
      for (const auto &match : matches) {
        // Both uprobes and fentry have a target (binary for uprobes, kernel
        // module for fentry).
        std::string func = match;
        std::string target = util::erase_prefix(func);
        std::string err;

        // Trying to attach to multiple fentry. If some of them fails on
        // argument resolution, do not fail hard, just print a warning and
        // continue with other functions.
        if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
          ap_args = bpftrace_.btf_->resolve_args(
              func, probe_type == ProbeType::fexit, true, false, err);

        } else if (probe_type == ProbeType::rawtracepoint) {
          ap_args = bpftrace_.btf_->resolve_raw_tracepoint_args(func, err);
        } else if (probe_type == ProbeType::tracepoint) {
          auto struct_name = TracepointFormatParser::get_struct_name(*ap);
          ap_args = bpftrace_.structs.Lookup(struct_name).lock();
          if (!ap_args) {
            err = ("No type found for tracepoint args: " + struct_name);
          }
        } else { // uprobe
          Dwarf *dwarf = bpftrace_.get_dwarf(target);
          if (dwarf)
            ap_args = dwarf->resolve_args(func);
          else
            ap->addWarning() << "No debuginfo found for " << target;
        }

        if (!ap_args) {
          ap->addWarning() << probetypeName(probe_type) << ap->func << ": "
                           << err;
          continue;
        }

        if (!probe_args)
          probe_args = ap_args;
        else if (*ap_args != *probe_args) {
          ap->addError() << "Probe has attach points with mixed arguments";
          break;
        }
      }
    } else {
      std::string err;
      // Resolving args for an explicit function failed, print an error and fail
      if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
        probe_args = bpftrace_.btf_->resolve_args(
            ap->func, probe_type == ProbeType::fexit, true, false, err);

      } else if (probe_type == ProbeType::rawtracepoint) {
        probe_args = bpftrace_.btf_->resolve_raw_tracepoint_args(ap->func, err);
      } else if (probe_type == ProbeType::tracepoint) {
        auto struct_name = TracepointFormatParser::get_struct_name(*ap);
        probe_args = bpftrace_.structs.Lookup(struct_name).lock();
        if (!probe_args) {
          err = ("No type found for tracepoint args: " + struct_name);
        }
      } else { // uprobe
        Dwarf *dwarf = bpftrace_.get_dwarf(ap->target);
        if (dwarf) {
          probe_args = dwarf->resolve_args(ap->func);
        } else {
          ap->addWarning() << "No debuginfo found for " << ap->target;
        }
        if (probe_args &&
            probe_args->fields.size() >= arch::Host::arguments().size()) {
          ap->addError() << "\'args\' builtin is not supported for "
                         << "probes with stack-passed arguments.";
        }
      }

      if (!probe_args) {
        ap->addError() << probetypeName(probe_type) << ap->func << ": " << err;
        return;
      }
    }

    // check if we already stored arguments for this probe
    auto args = bpftrace_.structs.Lookup(probe.args_typename()).lock();
    if (args && *args != *probe_args) {
      // we did, and it's different...trigger the error
      ap->addError() << "Probe has attach points with mixed arguments";
    } else {
      // store/save args for each ap for later processing
      bpftrace_.structs.Add(probe.args_typename(), std::move(probe_args));
    }
  }
}

void ArgsResolver::visit(Probe &probe)
{
  probe_ = &probe;
  visit(probe.block);
}

Pass CreateResolveArgsPass(std::unordered_set<ProbeType> &&probe_types)
{
  auto fn = [pt = std::move(probe_types)](ASTContext &ast,
                                          BPFtrace &b,
                                          ExpansionResult &expansions) {
    ArgsResolver analyser(b, expansions, pt);
    analyser.visit(ast.root);
  };

  return Pass::create("ResolveArgs", fn);
};

} // namespace bpftrace::ast
