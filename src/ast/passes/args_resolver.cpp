#include <algorithm>
#include <bpf/bpf.h>
#include <cassert>

#include "arch/arch.h"
#include "ast/passes/args_resolver.h"
#include "ast/passes/probe_expansion.h"
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
  explicit ArgsResolver(ASTContext &ast,
                        BPFtrace &bpftrace,
                        ExpansionResult &ap_expansions,
                        std::vector<ProbeType> probe_types)
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
  std::vector<ProbeType> probe_types_;
  Probe *probe_ = nullptr;
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
  auto probe_type = probe.get_probetype();
  if (probe.attach_points.empty() ||
      std::ranges::find(probe_types_, probe_type) == probe_types_.end()) {
    return;
  }

  // Everything should be expanded by now
  assert(probe.attach_points.size() == 1);
  auto *ap = probe.attach_points.at(0);
  std::shared_ptr<Struct> probe_args;
  std::string err;

  if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
    probe_args = bpftrace_.btf_->resolve_args(
        ap->func, probe_type == ProbeType::fexit, true, false, err);

  } else if (probe_type == ProbeType::rawtracepoint) {
    probe_args = bpftrace_.btf_->resolve_raw_tracepoint_args(ap->func, err);
  } else if (probe_type == ProbeType::tracepoint) {
    auto struct_name = TracepointFormatParser::get_struct_name(*ap);
    probe_args = bpftrace_.structs.Lookup(struct_name).lock();
  } else { // uprobe
    Dwarf *dwarf = bpftrace_.get_dwarf(ap->target);
    if (dwarf) {
      probe_args = dwarf->resolve_args(ap->func);
    } else {
      err = ("No debuginfo found for " + ap->target);
    }
  }

  if (probe_type == ProbeType::uprobe && probe_args &&
      probe_args->fields.size() >= arch::Host::arguments().size()) {
    ap->addError() << "\'args\' builtin is not supported for "
                   << "probes with stack-passed arguments.";
  }

  if (!probe_args) {
    ap->addError() << "Unable to get arguments for "
                   << probetypeName(probe_type) << ap->func << ": " << err;
    return;
  }

  bpftrace_.structs.Add(probe.args_typename(), std::move(probe_args));
}

void ArgsResolver::visit(Probe &probe)
{
  probe_ = &probe;
  visit(probe.block);
}

Pass CreateArgsResolverPass(std::vector<ProbeType> &&probe_types)
{
  auto fn = [pt = std::move(probe_types)](ASTContext &ast,
                                          BPFtrace &b,
                                          ExpansionResult &ap_expansions) {
    ArgsResolver resolver(ast, b, ap_expansions, pt);
    resolver.visit(ast.root);
  };

  return Pass::create("ArgsResolver", fn);
};

} // namespace bpftrace::ast
